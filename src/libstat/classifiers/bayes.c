/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Bayesian classifier
 */
#include "classifiers.h"
#include "rspamd.h"
#include "stat_internal.h"
#include "math.h"

#define msg_err_bayes(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,              \
													   "bayes", task->task_pool->tag.uid, \
													   RSPAMD_LOG_FUNC,                   \
													   __VA_ARGS__)
#define msg_warn_bayes(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING,               \
														"bayes", task->task_pool->tag.uid, \
														RSPAMD_LOG_FUNC,                   \
														__VA_ARGS__)
#define msg_info_bayes(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,                  \
														"bayes", task->task_pool->tag.uid, \
														RSPAMD_LOG_FUNC,                   \
														__VA_ARGS__)

INIT_LOG_MODULE_PUBLIC(bayes)

static inline GQuark
bayes_error_quark(void)
{
	return g_quark_from_static_string("bayes-error");
}

/**
 * Returns probability of chisquare > value with specified number of freedom
 * degrees
 * @param value value to test
 * @param freedom_deg number of degrees of freedom
 * @return
 */
static double
inv_chi_square(struct rspamd_task *task, double value, int freedom_deg)
{
	double prob, sum, m;
	int i;

	errno = 0;
	m = -value;
	prob = exp(value);

	if (errno == ERANGE) {
		/*
		 * e^x where x is large *NEGATIVE* number is OK, so we have a very strong
		 * confidence that inv-chi-square is close to zero
		 */
		msg_debug_bayes("exp overflow");

		if (value < 0) {
			return 0;
		}
		else {
			return 1.0;
		}
	}

	sum = prob;

	msg_debug_bayes("m: %f, probability: %g", m, prob);

	/*
	 * m is our confidence in class
	 * prob is e ^ x (small value since x is normally less than zero
	 * So we integrate over degrees of freedom and produce the total result
	 * from 1.0 (no confidence) to 0.0 (full confidence)
	 */
	for (i = 1; i < freedom_deg; i++) {
		prob *= m / (double) i;
		sum += prob;
		msg_debug_bayes("i=%d, probability: %g, sum: %g", i, prob, sum);
	}

	return MIN(1.0, sum);
}

struct bayes_task_closure {
	double *class_probs; /* Array of probabilities for each class */
	unsigned int nclasses; /* Number of classes */
	double meta_skip_prob;
	uint64_t processed_tokens;
	uint64_t total_hits;
	uint64_t text_tokens;
	struct rspamd_task *task;
};

/*
 * Mathematically we use pow(complexity, complexity), where complexity is the
 * window index
 */
static const double feature_weight[] = {0, 3125, 256, 27, 1, 0, 0, 0};

#define PROB_COMBINE(prob, cnt, weight, assumed) (((weight) * (assumed) + (cnt) * (prob)) / ((weight) + (cnt)))
/*
 * In this callback we calculate local probabilities for tokens
 */
static void
bayes_classify_token(struct rspamd_classifier *ctx,
					 rspamd_token_t *tok, struct bayes_task_closure *cl)
{
	unsigned int i;
	int id;
	unsigned int total_count = 0;
    double *class_counts, *class_freqs, *class_probs;
	struct rspamd_statfile *st;
	struct rspamd_task *task;
	const char *token_type = "txt";
	double fw, w, val;

	task = cl->task;

#if 0
	if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_LUA_META) {
		/* Ignore lua metatokens for now */
		return;
	}
#endif

	if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_META && cl->meta_skip_prob > 0) {
		val = rspamd_random_double_fast();

		if (val <= cl->meta_skip_prob) {
			if (tok->t1 && tok->t2) {
				msg_debug_bayes(
					"token(meta) %uL <%*s:%*s> probabilistically skipped",
					tok->data,
					(int) tok->t1->original.len, tok->t1->original.begin,
					(int) tok->t2->original.len, tok->t2->original.begin);
			}

			return;
		}
	}

	/* Allocate arrays for class-specific counts and probabilities */
    class_counts = g_new0(double, ctx->statfiles_ids->len);
    class_freqs = g_new0(double, ctx->statfiles_ids->len);
    class_probs = g_new0(double, ctx->statfiles_ids->len);

	for (i = 0; i < ctx->statfiles_ids->len; i++) {
		id = g_array_index(ctx->statfiles_ids, int, i);
		st = g_ptr_array_index(ctx->ctx->statfiles, id);
		g_assert(st != NULL);
		val = tok->values[id];

		if (val > 0) {
            class_counts[i] += val;
            total_count += val;
            cl->total_hits += val;
        }
	}

	/* Probability for this token */
	if (total_count >= ctx->cfg->min_token_hits) {
		double total_freq = 0.0;

        for (i = 0; i < ctx->statfiles_ids->len; i++) {
            id = g_array_index(ctx->statfiles_ids, int, i);
            st = g_ptr_array_index(ctx->ctx->statfiles, id);
            class_freqs[i] = class_counts[i] / MAX(1.0, (double)st->learns);
            total_freq += class_freqs[i];
        }

		for (i = 0; i < ctx->statfiles_ids->len; i++) {
            class_probs[i] = total_freq > 0 ? class_freqs[i] / total_freq : 0.5;
        }

		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_UNIGRAM) {
			fw = 1.0;
		}
		else {
			fw = feature_weight[tok->window_idx %
								G_N_ELEMENTS(feature_weight)];
		}


		w = (fw * total_count) / (1.0 + fw * total_count);

		for (i = 0; i < ctx->statfiles_ids->len; i++) {
            double bayes_prob = PROB_COMBINE(class_probs[i], total_count, w, 0.5);

            if ((bayes_prob > 0.5 && bayes_prob < 0.5 + ctx->cfg->min_prob_strength) ||
                (bayes_prob < 0.5 && bayes_prob > 0.5 - ctx->cfg->min_prob_strength)) {
                continue; /* Skip tokens with weak probabilities for this class */
            }

            cl->class_probs[i] += log(bayes_prob);
        }
		cl->processed_tokens++;

		if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_META)) {
			cl->text_tokens++;
		}
		else {
			token_type = "meta";
		}

		if (tok->t1 && tok->t2) {
            GString *prob_str = g_string_new(NULL);
            for (i = 0; i < ctx->statfiles_ids->len; i++) {
                id = g_array_index(ctx->statfiles_ids, int, i);
                st = g_ptr_array_index(ctx->ctx->statfiles, id);
                g_string_append_printf(prob_str, "%s: %.3f; ", st->stcf->symbol, class_probs[i]);
            }
            msg_debug_bayes("token(%s) %uL <%*s:%*s>: weight: %f, cf: %f, "
                            "total_count: %ud, probs: %s",
                            token_type, tok->data,
                            (int) tok->t1->stemmed.len, tok->t1->stemmed.begin,
                            (int) tok->t2->stemmed.len, tok->t2->stemmed.begin,
                            fw, w, total_count, prob_str->str);
            g_string_free(prob_str, TRUE);
		}
		else {
            GString *prob_str = g_string_new(NULL);
            for (i = 0; i < ctx->statfiles_ids->len; i++) {
                id = g_array_index(ctx->statfiles_ids, int, i);
                st = g_ptr_array_index(ctx->ctx->statfiles, id);
                g_string_append_printf(prob_str, "%s: %.3f; ", st->stcf->symbol, class_probs[i]);
            }
            msg_debug_bayes("token(%s) %uL <?:?>: weight: %f, cf: %f, "
                            "total_count: %ud, probs: %s",
                            token_type, tok->data,
                            fw, w, total_count, prob_str->str);
            g_string_free(prob_str, TRUE);
        }
	}
}


gboolean
bayes_init(struct rspamd_config *cfg,
		   struct ev_loop *ev_base,
		   struct rspamd_classifier *cl)
{
	cl->cfg->flags |= RSPAMD_FLAG_CLASSIFIER_INTEGER;

	return TRUE;
}

void bayes_fin(struct rspamd_classifier *cl)
{
}

gboolean
bayes_classify(struct rspamd_classifier *ctx,
			   GPtrArray *tokens,
			   struct rspamd_task *task)
{
	double final_prob, h, s, *pprob;
	char sumbuf[32];
	struct rspamd_statfile *st = NULL;
	struct bayes_task_closure cl;
	rspamd_token_t *tok;
	unsigned int i, text_tokens = 0;
	int id;

	g_assert(ctx != NULL);
	g_assert(tokens != NULL);

	memset(&cl, 0, sizeof(cl));
	cl.nclasses = ctx->statfiles_ids->len;
	cl.class_probs = g_new0(double, cl.nclasses);
	cl.task = task;

	/* Check min learns */
	if (ctx->cfg->min_learns > 0) {
		for (i = 0; i < ctx->statfiles_ids->len; i++) {
			id = g_array_index(ctx->statfiles_ids, int, i);
			st = g_ptr_array_index(ctx->ctx->statfiles, id);
			if (st->learns < ctx->cfg->min_learns) {
				msg_info_task("not classified for %s. The class needs more "
							"training samples. Currently: %ul; minimum %ud required",
							st->stcf->symbol, st->learns, ctx->cfg->min_learns);
				g_free(cl.class_probs);
				return TRUE;
			}
		}
	}

	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index(tokens, i);
		if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_META)) {
			text_tokens++;
		}
	}

	if (text_tokens == 0) {
		msg_info_task("skipped classification as there are no text tokens. "
					  "Total tokens: %ud",
					  tokens->len);

		return TRUE;
	}

	/*
	 * Skip some metatokens if we don't have enough text tokens
	 */
	if (text_tokens > tokens->len - text_tokens) {
		cl.meta_skip_prob = 0.0;
	}
	else {
		cl.meta_skip_prob = 1.0 - text_tokens / tokens->len;
	}

	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index(tokens, i);

		bayes_classify_token(ctx, tok, &cl);
	}

	if (cl.processed_tokens == 0) {
		msg_info_bayes("no tokens found in bayes database "
					   "(%ud total tokens, %ud text tokens), ignore stats",
					   tokens->len, text_tokens);

		return TRUE;
	}

	if (ctx->cfg->min_tokens > 0 &&
		cl.text_tokens < (int) (ctx->cfg->min_tokens * 0.1)) {
		msg_info_bayes("ignore bayes probability since we have "
					   "found too few text tokens: %uL (of %ud checked), "
					   "at least %d required",
					   cl.text_tokens,
					   text_tokens,
					   (int) (ctx->cfg->min_tokens * 0.1));

		return TRUE;
	}

	if (cl.spam_prob > -300 && cl.ham_prob > -300) {
		/* Fisher value is low enough to apply inv_chi_square */
		h = 1 - inv_chi_square(task, cl.spam_prob, cl.processed_tokens);
		s = 1 - inv_chi_square(task, cl.ham_prob, cl.processed_tokens);
	}
	else {
		/* Use naive method */
		if (cl.spam_prob < cl.ham_prob) {
			h = (1.0 - exp(cl.spam_prob - cl.ham_prob)) /
				(1.0 + exp(cl.spam_prob - cl.ham_prob));
			s = 1.0 - h;
		}
		else {
			s = (1.0 - exp(cl.ham_prob - cl.spam_prob)) /
				(1.0 + exp(cl.ham_prob - cl.spam_prob));
			h = 1.0 - s;
		}
	}

	if (isfinite(s) && isfinite(h)) {
		final_prob = (s + 1.0 - h) / 2.;
		msg_debug_bayes(
			"got ham probability %.2f -> %.2f and spam probability %.2f -> %.2f,"
			" %L tokens processed of %ud total tokens;"
			" %uL text tokens found of %ud text tokens)",
			cl.ham_prob,
			h,
			cl.spam_prob,
			s,
			cl.processed_tokens,
			tokens->len,
			cl.text_tokens,
			text_tokens);
	}
	else {
		/*
		 * We have some overflow, hence we need to check which class
		 * is NaN
		 */
		if (isfinite(h)) {
			final_prob = 1.0;
			msg_debug_bayes("spam class is full: no"
							" ham samples");
		}
		else if (isfinite(s)) {
			final_prob = 0.0;
			msg_debug_bayes("ham class is full: no"
							" spam samples");
		}
		else {
			final_prob = 0.5;
			msg_warn_bayes("spam and ham classes are both full");
		}
	}

	pprob = rspamd_mempool_alloc(task->task_pool, sizeof(*pprob));
	*pprob = final_prob;
	rspamd_mempool_set_variable(task->task_pool, "bayes_prob", pprob, NULL);

	if (cl.processed_tokens > 0 && fabs(final_prob - 0.5) > 0.05) {
		/* Now we can have exactly one HAM and exactly one SPAM statfiles per classifier */
		for (i = 0; i < ctx->statfiles_ids->len; i++) {
			id = g_array_index(ctx->statfiles_ids, int, i);
			st = g_ptr_array_index(ctx->ctx->statfiles, id);

			if (final_prob > 0.5 && st->stcf->is_spam) {
				break;
			}
			else if (final_prob < 0.5 && !st->stcf->is_spam) {
				break;
			}
		}

		/* Correctly scale HAM */
		if (final_prob < 0.5) {
			final_prob = 1.0 - final_prob;
		}

		/*
		 * Bayes p is from 0.5 to 1.0, but confidence is from 0 to 1, so
		 * we need to rescale it to display correctly
		 */
		rspamd_snprintf(sumbuf, sizeof(sumbuf), "%.2f%%",
						(final_prob - 0.5) * 200.);
		final_prob = rspamd_normalize_probability(final_prob, 0.5);
		g_assert(st != NULL);

		if (final_prob > 1 || final_prob < 0) {
			msg_err_bayes("internal error: probability %f is outside of the "
						  "allowed range [0..1]",
						  final_prob);

			if (final_prob > 1) {
				final_prob = 1.0;
			}
			else {
				final_prob = 0.0;
			}
		}

		rspamd_task_insert_result(task,
								  st->stcf->symbol,
								  final_prob,
								  sumbuf);
	}

	return TRUE;
}

gboolean
bayes_learn_spam(struct rspamd_classifier *ctx,
				 GPtrArray *tokens,
				 struct rspamd_task *task,
				 gboolean is_spam,
				 gboolean unlearn,
				 GError **err)
{
	unsigned int i, j, total_cnt, spam_cnt, ham_cnt;
	int id;
	struct rspamd_statfile *st;
	rspamd_token_t *tok;
	gboolean incrementing;

	g_assert(ctx != NULL);
	g_assert(tokens != NULL);

	incrementing = ctx->cfg->flags & RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND;

	for (i = 0; i < tokens->len; i++) {
		total_cnt = 0;
		spam_cnt = 0;
		ham_cnt = 0;
		tok = g_ptr_array_index(tokens, i);

		for (j = 0; j < ctx->statfiles_ids->len; j++) {
			id = g_array_index(ctx->statfiles_ids, int, j);
			st = g_ptr_array_index(ctx->ctx->statfiles, id);
			g_assert(st != NULL);

			if (!!st->stcf->is_spam == !!is_spam) {
				if (incrementing) {
					tok->values[id] = 1;
				}
				else {
					tok->values[id]++;
				}

				total_cnt += tok->values[id];

				if (st->stcf->is_spam) {
					spam_cnt += tok->values[id];
				}
				else {
					ham_cnt += tok->values[id];
				}
			}
			else {
				if (tok->values[id] > 0 && unlearn) {
					/* Unlearning */
					if (incrementing) {
						tok->values[id] = -1;
					}
					else {
						tok->values[id]--;
					}

					if (st->stcf->is_spam) {
						spam_cnt += tok->values[id];
					}
					else {
						ham_cnt += tok->values[id];
					}
					total_cnt += tok->values[id];
				}
				else if (incrementing) {
					tok->values[id] = 0;
				}
			}
		}

		if (tok->t1 && tok->t2) {
			msg_debug_bayes("token %uL <%*s:%*s>: window: %d, total_count: %d, "
							"spam_count: %d, ham_count: %d",
							tok->data,
							(int) tok->t1->stemmed.len, tok->t1->stemmed.begin,
							(int) tok->t2->stemmed.len, tok->t2->stemmed.begin,
							tok->window_idx, total_cnt, spam_cnt, ham_cnt);
		}
		else {
			msg_debug_bayes("token %uL <?:?>: window: %d, total_count: %d, "
							"spam_count: %d, ham_count: %d",
							tok->data,
							tok->window_idx, total_cnt, spam_cnt, ham_cnt);
		}
	}

	return TRUE;
}
