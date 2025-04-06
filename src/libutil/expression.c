/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "expression.h"
#include "printf.h"
#include "regexp.h"
#include "util.h"
#include "utlist.h"
#include "ottery.h"
#include "libserver/logger.h"
#include "libcryptobox/cryptobox.h"
#include <math.h>

#define RSPAMD_EXPR_FLAG_NEGATE (1 << 0)
#define RSPAMD_EXPR_FLAG_PROCESSED (1 << 1)

#define MIN_RESORT_EVALS 50
#define MAX_RESORT_EVALS 150

enum rspamd_expression_elt_type {
	ELT_OP = 0,
	ELT_ATOM,
	ELT_LIMIT,
	ELT_CLASS  /* New: Class identifier for multiclass */
};

enum rspamd_expression_op_flag {
	RSPAMD_EXPRESSION_UNARY = 1u << 0u,
	RSPAMD_EXPRESSION_BINARY = 1u << 1u,
	RSPAMD_EXPRESSION_NARY = 1u << 2u,
	RSPAMD_EXPRESSION_ARITHMETIC = 1u << 3u,
	RSPAMD_EXPRESSION_LOGICAL = 1u << 4u,
	RSPAMD_EXPRESSION_COMPARISON = 1u << 5u,
};

/* New: Structure to hold multiclass results */
struct rspamd_expression_result {
	enum {
		RSPAMD_RESULT_DOUBLE,
		RSPAMD_RESULT_STRING  /* New: For class labels */
	} type;
	union {
		double dval;
		char *sval;  /* New: String value for class labels */
	} value;
};

struct rspamd_expression_operation {
	enum rspamd_expression_op op;
	unsigned int logical_priority;
	unsigned int op_flags;
};

struct rspamd_expression_elt {
	enum rspamd_expression_elt_type type;
	union {
		rspamd_expression_atom_t *atom;
		struct rspamd_expression_operation op;
		double lim;
		char *class_name;  /* New: Class label as string */
	} p;

	int flags;
	int priority;
	struct rspamd_expression_result value;  /* Updated: Supports multiclass */
};

struct rspamd_expression {
	const struct rspamd_atom_subr *subr;
	GArray *expressions;
	GPtrArray *expression_stack;
	GNode *ast;
	char *log_id;
	unsigned int next_resort;
	unsigned int evals;
};

struct rspamd_expr_process_data {
	gpointer *ud;
	int flags;
	/* != NULL if trace is collected */
	GPtrArray *trace;
	rspamd_expression_process_cb process_closure;
};

#define msg_debug_expression(...) rspamd_conditional_debug_fast(NULL, NULL,                                        \
																rspamd_expression_log_id, "expression", e->log_id, \
																RSPAMD_LOG_FUNC,                                   \
																__VA_ARGS__)

#ifdef DEBUG_EXPRESSIONS
#define msg_debug_expression_verbose(...) rspamd_conditional_debug_fast(NULL, NULL,                                        \
																		rspamd_expression_log_id, "expression", e->log_id, \
																		RSPAMD_LOG_FUNC,                                   \
																		__VA_ARGS__)
#else
#define msg_debug_expression_verbose(...) \
	do {                                  \
	} while (0)
#endif

INIT_LOG_MODULE(expression)

static GQuark
rspamd_expr_quark(void)
{
	return g_quark_from_static_string("rspamd-expression");
}

static const char *RSPAMD_CONST_FUNCTION
rspamd_expr_op_to_str(enum rspamd_expression_op op);
static const char *
rspamd_expr_op_to_str(enum rspamd_expression_op op)
{
	const char *op_str = NULL;

	switch (op) {
	case OP_AND:
		op_str = "&";
		break;
	case OP_OR:
		op_str = "|";
		break;
	case OP_MULT:
		op_str = "*";
		break;
	case OP_PLUS:
		op_str = "+";
		break;
	case OP_MINUS:
		op_str = "-";
		break;
	case OP_DIVIDE:
		op_str = "/";
		break;
	case OP_NOT:
		op_str = "!";
		break;
	case OP_GE:
		op_str = ">=";
		break;
	case OP_GT:
		op_str = ">";
		break;
	case OP_LE:
		op_str = "<=";
		break;
	case OP_LT:
		op_str = "<";
		break;
	case OP_EQ:
		op_str = "==";
		break;
	case OP_NE:
		op_str = "!=";
		break;
	case OP_OBRACE:
		op_str = "(";
		break;
	case OP_CBRACE:
		op_str = ")";
		break;
	case OP_SELECT:  /* New: Ternary operator for multiclass */
		op_str = "select";
		break;
	default:
		op_str = "???";
		break;
	}

	return op_str;
}

#define G_ARRAY_LAST(ar, type) (&g_array_index((ar), type, (ar)->len - 1))

static void
rspamd_expr_stack_elt_push(GPtrArray *stack,
						   gpointer elt)
{
	g_ptr_array_add(stack, elt);
}


static gpointer
rspamd_expr_stack_elt_pop(GPtrArray *stack)
{
	gpointer e;
	int idx;

	if (stack->len == 0) {
		return NULL;
	}

	idx = stack->len - 1;
	e = g_ptr_array_index(stack, idx);
	g_ptr_array_remove_index_fast(stack, idx);

	return e;
}


static void
rspamd_expr_stack_push(struct rspamd_expression *expr,
					   gpointer elt)
{
	rspamd_expr_stack_elt_push(expr->expression_stack, elt);
}

static gpointer
rspamd_expr_stack_pop(struct rspamd_expression *expr)
{
	return rspamd_expr_stack_elt_pop(expr->expression_stack);
}

static gpointer
rspamd_expr_stack_peek(struct rspamd_expression *expr)
{
	gpointer e;
	int idx;
	GPtrArray *stack = expr->expression_stack;

	if (stack->len == 0) {
		return NULL;
	}

	idx = stack->len - 1;
	e = g_ptr_array_index(stack, idx);

	return e;
}

/*
 * Return operation priority
 */
static int RSPAMD_CONST_FUNCTION
rspamd_expr_logic_priority(enum rspamd_expression_op op);
static int
rspamd_expr_logic_priority(enum rspamd_expression_op op)
{
	int ret = 0;

	switch (op) {
	case OP_NOT:
		ret = 7;
		break;
	case OP_MULT:
	case OP_DIVIDE:
		ret = 6;
		break;
	case OP_PLUS:
	case OP_MINUS:
		ret = 5;
		break;
	case OP_GE:
	case OP_GT:
	case OP_LE:
	case OP_LT:
	case OP_EQ:
	case OP_NE:
		ret = 4;
		break;
	case OP_AND:
		ret = 3;
		break;
	case OP_OR:
	case OP_SELECT:  /* New: Same priority as OR */
		ret = 2;
		break;
	case OP_OBRACE:
	case OP_CBRACE:
		ret = 1;
		break;
	case OP_INVALID:
		ret = -1;
		break;
	}

	return ret;
}

static unsigned int RSPAMD_CONST_FUNCTION
rspamd_expr_op_flags(enum rspamd_expression_op op);

static unsigned int
rspamd_expr_op_flags(enum rspamd_expression_op op)
{
	unsigned int ret = 0;

	switch (op) {
	case OP_NOT:
		ret |= RSPAMD_EXPRESSION_UNARY | RSPAMD_EXPRESSION_LOGICAL;
		break;
	case OP_MULT:
		ret |= RSPAMD_EXPRESSION_NARY | RSPAMD_EXPRESSION_ARITHMETIC;
		break;
	case OP_DIVIDE:
		ret |= RSPAMD_EXPRESSION_BINARY | RSPAMD_EXPRESSION_ARITHMETIC;
		break;
	case OP_PLUS:
		ret |= RSPAMD_EXPRESSION_NARY | RSPAMD_EXPRESSION_ARITHMETIC;
		break;
	case OP_MINUS:
		ret |= RSPAMD_EXPRESSION_BINARY | RSPAMD_EXPRESSION_ARITHMETIC;
		break;
	case OP_GE:
	case OP_GT:
	case OP_LE:
	case OP_LT:
	case OP_EQ:
	case OP_NE:
		ret |= RSPAMD_EXPRESSION_BINARY | RSPAMD_EXPRESSION_COMPARISON;
		break;
	case OP_AND:
	case OP_OR:
		ret |= RSPAMD_EXPRESSION_NARY | RSPAMD_EXPRESSION_LOGICAL;
		break;
	case OP_SELECT:  /* New: Ternary operator (condition, true_val, false_val) */
		ret |= RSPAMD_EXPRESSION_NARY;
		break;
	case OP_OBRACE:
	case OP_CBRACE:
	case OP_INVALID:
		break;
	}

	return ret;
}

/*
 * Return FALSE if symbol is not operation symbol (operand)
 * Return TRUE if symbol is operation symbol
 */
static gboolean RSPAMD_CONST_FUNCTION
rspamd_expr_is_operation_symbol(char a);
static gboolean
rspamd_expr_is_operation_symbol(char a)
{
	switch (a) {
	case '!':
	case '&':
	case '|':
	case '(':
	case ')':
	case '>':
	case '<':
	case '+':
	case '*':
	case '-':
	case '/':
	case '=':
		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_expr_is_operation(struct rspamd_expression *e,
						 const char *p, const char *end, rspamd_regexp_t *num_re)
{
	if (rspamd_expr_is_operation_symbol(*p)) {
		if (p + 1 < end) {
			char t = *(p + 1);

			if (t == ':') {
				/* Special case, treat it as an atom */
			}
			else if (*p == '/') {
				/* Lookahead for division operation to distinguish from regexp */
				const char *track = p + 1;

				/* Skip spaces */
				while (track < end && g_ascii_isspace(*track)) {
					track++;
				}

				/* Check for a number */
				if (rspamd_regexp_search(num_re,
										 track,
										 end - track,
										 NULL,
										 NULL,
										 FALSE,
										 NULL)) {
					msg_debug_expression_verbose("found divide operation");
					return TRUE;
				}

				msg_debug_expression_verbose("false divide operation");
				/* Fallback to PARSE_ATOM state */
			}
			else if (*p == '-') {
				/* - is used in composites, so we need to distinguish - from
				 * 1) unary minus of a limit!
				 * 2) -BLAH in composites
				 * Decision is simple: require a space after binary `-` op
				 */
				if (g_ascii_isspace(t)) {
					return TRUE;
				}
				/* Fallback to PARSE_ATOM state */
				msg_debug_expression_verbose("false minus operation");
			}
			else {
				/* Generic operation */
				return TRUE;
			}
		}
		else {
			/* Last op */
			return TRUE;
		}
	}

	return FALSE;
}

/* Return character representation of operation */
static enum rspamd_expression_op
rspamd_expr_str_to_op(const char *a, const char *end, const char **next)
{
	enum rspamd_expression_op op = OP_INVALID;

	g_assert(a < end);

	switch (*a) {
	case '!':
	case '&':
	case '|':
	case '+':
	case '*':
	case '/':
	case '-':
	case '(':
	case ')':
	case '=': {
		if (a < end - 1) {
			if ((a[0] == '&' && a[1] == '&') ||
				(a[0] == '|' && a[1] == '|') ||
				(a[0] == '!' && a[1] == '=') ||
				(a[0] == '=' && a[1] == '=')) {
				*next = a + 2;
			}
			else {
				*next = a + 1;
			}
		}
		else {
			*next = end;
		}
		/* XXX: not especially effective */
		switch (*a) {
		case '!':
			if (a < end - 1 && a[1] == '=') {
				op = OP_NE;
			}
			else {
				op = OP_NOT;
			}
			break;
		case '&':
			op = OP_AND;
			break;
		case '*':
			op = OP_MULT;
			break;
		case '|':
			op = OP_OR;
			break;
		case '+':
			op = OP_PLUS;
			break;
		case '/':
			op = OP_DIVIDE;
			break;
		case '-':
			op = OP_MINUS;
			break;
		case '=':
			op = OP_EQ;
			break;
		case ')':
			op = OP_CBRACE;
			break;
		case '(':
			op = OP_OBRACE;
			break;
		default:
			op = OP_INVALID;
			break;
		}
		break;
	}
	case 'O':
	case 'o':
		if ((gulong) (end - a) >= sizeof("or") &&
			g_ascii_strncasecmp(a, "or", sizeof("or") - 1) == 0) {
			*next = a + sizeof("or") - 1;
			op = OP_OR;
		}
		break;
	case 'A':
	case 'a':
		if ((gulong) (end - a) >= sizeof("and") &&
			g_ascii_strncasecmp(a, "and", sizeof("and") - 1) == 0) {
			*next = a + sizeof("and") - 1;
			op = OP_AND;
		}
		break;
	case 'N':
	case 'n':
		if ((gulong) (end - a) >= sizeof("not") &&
			g_ascii_strncasecmp(a, "not", sizeof("not") - 1) == 0) {
			*next = a + sizeof("not") - 1;
			op = OP_NOT;
		}
		break;
	case 'S':
	case 's':
		if ((gulong) (end - a) >= sizeof("select") &&
			g_ascii_strncasecmp(a, "select", sizeof("select") - 1) == 0) {  /* New: Parse 'select' */
			*next = a + sizeof("select") - 1;
			op = OP_SELECT;
		}
		break;
	case '>':
		if (a < end - 1 && a[1] == '=') {
			*next = a + 2;
			op = OP_GE;
		}
		else {
			*next = a + 1;
			op = OP_GT;
		}
		break;
	case '<':
		if (a < end - 1 && a[1] == '=') {
			*next = a + 2;
			op = OP_LE;
		}
		else {
			*next = a + 1;
			op = OP_LT;
		}
		break;
	default:
		op = OP_INVALID;
		break;
	}

	return op;
}

static void
rspamd_expression_destroy(struct rspamd_expression *expr)
{
	unsigned int i;
	struct rspamd_expression_elt *elt;

	if (expr != NULL) {

		if (expr->subr->destroy) {
			/* Free atoms */
			for (i = 0; i < expr->expressions->len; i++) {
				elt = &g_array_index(expr->expressions,
									 struct rspamd_expression_elt, i);

				if (elt->type == ELT_ATOM) {
					expr->subr->destroy(elt->p.atom);
				}
				/* New: Free class names if allocated */
				else if (elt->type == ELT_CLASS && elt->p.class_name) {
					g_free(elt->p.class_name);
				}
			}
		}

		if (expr->expressions) {
			g_array_free(expr->expressions, TRUE);
		}
		if (expr->expression_stack) {
			g_ptr_array_free(expr->expression_stack, TRUE);
		}
		if (expr->ast) {
			g_node_destroy(expr->ast);
		}
		if (expr->log_id) {
			g_free(expr->log_id);
		}

		g_free(expr);
	}
}

static gboolean
rspamd_ast_add_node(struct rspamd_expression *e,
					GPtrArray *operands,
					struct rspamd_expression_elt *op,
					GError **err)
{
	GNode *res, *a1, *a2, *test;

	g_assert(op->type == ELT_OP);

	if (op->p.op.op_flags & RSPAMD_EXPRESSION_UNARY) {
		/* Unary operator */
		struct rspamd_expression_elt *test_elt;

		res = g_node_new(op);
		a1 = rspamd_expr_stack_elt_pop(operands);

		if (a1 == NULL) {
			g_set_error(err, rspamd_expr_quark(), EINVAL, "no operand to "
														  "unary '%s' operation",
						rspamd_expr_op_to_str(op->p.op.op));
			g_node_destroy(res);

			return FALSE;
		}

		g_node_append(res, a1);
		test_elt = a1->data;

		if (test_elt->type == ELT_ATOM) {
			test_elt->p.atom->parent = res;
			msg_debug_expression("added unary op %s to AST; operand: %*s",
								 rspamd_expr_op_to_str(op->p.op.op),
								 (int) test_elt->p.atom->len, test_elt->p.atom->str);
		}
		else {
			msg_debug_expression("added unary op %s to AST; operand type: %d",
								 rspamd_expr_op_to_str(op->p.op.op),
								 test_elt->type);
		}
	}
	else {
		struct rspamd_expression_elt *e1, *e2;
		/* For binary/nary operators we might want to examine chains */
		a2 = rspamd_expr_stack_elt_pop(operands);
		a1 = rspamd_expr_stack_elt_pop(operands);

		if (a2 == NULL) {
			g_set_error(err, rspamd_expr_quark(), EINVAL, "no left operand to "
														  "'%s' operation",
						rspamd_expr_op_to_str(op->p.op.op));
			return FALSE;
		}

		if (a1 == NULL) {
			g_set_error(err, rspamd_expr_quark(), EINVAL, "no right operand to "
														  "'%s' operation",
						rspamd_expr_op_to_str(op->p.op.op));
			return FALSE;
		}

		/* New: Special handling for OP_SELECT (ternary operator) */
		if (op->p.op.op == OP_SELECT) {
			GNode *a3 = rspamd_expr_stack_elt_pop(operands);
			if (a3 == NULL) {
				g_set_error(err, rspamd_expr_quark(), EINVAL, "no condition operand to "
															  "'select' operation");
				return FALSE;
			}
			res = g_node_new(op);
			g_node_append(res, a3);  /* Condition */
			g_node_append(res, a1);  /* True value */
			g_node_append(res, a2);  /* False value */
		}
		/* Nary stuff */
		else if (op->p.op.op_flags & RSPAMD_EXPRESSION_NARY) {
			/*
			 * We convert a set of ops like X + Y + Z to a nary tree like
			 * X Y Z +
			 * for the longest possible prefix of atoms/limits
			 */

			/* First try with a1 */
			test = a1;
			e1 = test->data;

			if (e1->type == ELT_OP && e1->p.op.op == op->p.op.op) {
				/* Add children */
				g_node_append(test, a2);
				rspamd_expr_stack_elt_push(operands, a1);

				msg_debug_expression("added nary op %s to AST merged with the first operand",
									 rspamd_expr_op_to_str(op->p.op.op));

				return TRUE;
			}

			/* Now test a2 */
			test = a2;
			e2 = test->data;

			if (e2->type == ELT_OP && e2->p.op.op == op->p.op.op) {
				/* Add children */
				g_node_prepend(test, a1);
				rspamd_expr_stack_elt_push(operands, a2);

				msg_debug_expression("added nary op %s to AST merged with the second operand",
									 rspamd_expr_op_to_str(op->p.op.op));

				return TRUE;
			}

			/* No optimizations possible, so create a new level */
			res = g_node_new(op);
			g_node_append(res, a1);
			g_node_append(res, a2);
		}
		else {
			/* Binary operator */
			res = g_node_new(op);
			g_node_append(res, a1);
			g_node_append(res, a2);
		}

		e1 = a1->data;
		e2 = a2->data;

		if (e1->type == ELT_ATOM) {
			e1->p.atom->parent = res;
		}

		if (e2->type == ELT_ATOM) {
			e2->p.atom->parent = res;
		}

		if (e1->type == ELT_ATOM && e2->type == ELT_ATOM) {
			msg_debug_expression("added binary op %s to AST; operands: (%*s; %*s)",
								 rspamd_expr_op_to_str(op->p.op.op),
								 (int) e1->p.atom->len, e1->p.atom->str,
								 (int) e2->p.atom->len, e2->p.atom->str);
		}
		else {
			msg_debug_expression("added binary op %s to AST; operands (types): (%d; %d)",
								 rspamd_expr_op_to_str(op->p.op.op),
								 e1->type,
								 e2->type);
		}
	}

	/* Push back resulting node to the stack */
	rspamd_expr_stack_elt_push(operands, res);

	return TRUE;
}

static gboolean
rspamd_ast_priority_traverse(GNode *node, gpointer d)
{
	struct rspamd_expression_elt *elt = node->data, *cur_elt;
	struct rspamd_expression *expr = d;
	int cnt = 0;
	GNode *cur;

	if (node->children) {
		cur = node->children;
		while (cur) {
			cur_elt = cur->data;
			cnt += cur_elt->priority;
			cur = cur->next;
		}
		elt->priority = cnt;
	}
	else {
		/* It is atom or limit */
		g_assert(elt->type != ELT_OP);

		if (elt->type == ELT_LIMIT || elt->type == ELT_CLASS) {  /* Updated: Include ELT_CLASS */
			/* Always push limit/class first */
			elt->priority = 0;
		}
		else {
			elt->priority = RSPAMD_EXPRESSION_MAX_PRIORITY;

			if (expr->subr->priority != NULL) {
				elt->priority = RSPAMD_EXPRESSION_MAX_PRIORITY -
								expr->subr->priority(elt->p.atom);
			}
			elt->p.atom->hits = 0;
		}
	}

	return FALSE;
}

#define ATOM_PRIORITY(a) ((a)->p.atom->hits / ((a)->p.atom->exec_time.mean > 0 ? (a)->p.atom->exec_time.mean * 10000000 : 1.0))

static int
rspamd_ast_priority_cmp(GNode *a, GNode *b)
{
	struct rspamd_expression_elt *ea = a->data, *eb = b->data;
	double w1, w2;

	if (ea->type == ELT_LIMIT || ea->type == ELT_CLASS) {  /* Updated: Include ELT_CLASS */
		return 1;
	}
	else if (eb->type == ELT_LIMIT || eb->type == ELT_CLASS) {
		return -1;
	}

	/* Special logic for atoms */
	if (ea->type == ELT_ATOM && eb->type == ELT_ATOM &&
		ea->priority == eb->priority) {
		w1 = ATOM_PRIORITY(ea);
		w2 = ATOM_PRIORITY(eb);

		ea->p.atom->hits = 0;

		return w1 - w2;
	}
	else {
		return ea->priority - eb->priority;
	}
}

static gboolean
rspamd_ast_resort_traverse(GNode *node, gpointer unused)
{
	GNode *children, *last;
	struct rspamd_expression_elt *elt;

	elt = (struct rspamd_expression_elt *) node->data;

	/*
	 * We sort merely logical operations, everything else is dangerous
	 */
	if (elt->type == ELT_OP && elt->p.op.op_flags & RSPAMD_EXPRESSION_LOGICAL) {

		if (node->children) {

			children = node->children;
			last = g_node_last_sibling(children);
			/* Needed for utlist compatibility */
			children->prev = last;
			DL_SORT(node->children, rspamd_ast_priority_cmp);
			/* Restore GLIB compatibility */
			children = node->children;
			children->prev = NULL;
		}
	}

	return FALSE;
}

static struct rspamd_expression_elt *
rspamd_expr_dup_elt(rspamd_mempool_t *pool, struct rspamd_expression_elt *elt)
{
	struct rspamd_expression_elt *n;

	n = rspamd_mempool_alloc(pool, sizeof(*n));
	memcpy(n, elt, sizeof(*n));

	/* New: Duplicate class_name if present */
	if (elt->type == ELT_CLASS && elt->p.class_name) {
		n->p.class_name = rspamd_mempool_strdup(pool, elt->p.class_name);
	}

	return n;
}

gboolean
rspamd_parse_expression(const char *line, gsize len,
						const struct rspamd_atom_subr *subr, gpointer subr_data,
						rspamd_mempool_t *pool, GError **err,
						struct rspamd_expression **target)
{
	struct rspamd_expression *e;
	struct rspamd_expression_elt elt;
	rspamd_expression_atom_t *atom;
	rspamd_regexp_t *num_re;
	enum rspamd_expression_op op, op_stack;
	const char *p, *c, *end;
	GPtrArray *operand_stack;
	GNode *tmp;

	enum {
		PARSE_ATOM = 0,
		PARSE_OP,
		PARSE_LIM,
		PARSE_CLASS,  /* New: Parse class identifiers */
		SKIP_SPACES
	} state = PARSE_ATOM;

	g_assert(line != NULL);
	g_assert(subr != NULL && subr->parse != NULL);

	if (len == 0) {
		len = strlen(line);
	}

	memset(&elt, 0, sizeof(elt));
	num_re = rspamd_regexp_cache_create(NULL,
										"/^(?:[+-]?([0-9]*[.])?[0-9]+)(?:\\s+|[)]|$)/", NULL, NULL);

	p = line;
	c = line;
	end = line + len;
	e = g_malloc0(sizeof(*e));
	e->expressions = g_array_new(FALSE, FALSE,
								 sizeof(struct rspamd_expression_elt));
	operand_stack = g_ptr_array_sized_new(32);
	e->ast = NULL;
	e->expression_stack = g_ptr_array_sized_new(32);
	e->subr = subr;
	e->evals = 0;
	e->next_resort = ottery_rand_range(MAX_RESORT_EVALS) + MIN_RESORT_EVALS;
	e->log_id = g_malloc0(RSPAMD_LOG_ID_LEN + 1);
	uint64_t h = rspamd_cryptobox_fast_hash(line, len, 0xdeadbabe);
	rspamd_snprintf(e->log_id, RSPAMD_LOG_ID_LEN + 1, "%xL", h);
	msg_debug_expression("start to parse expression '%*s'", (int) len, line);

	/* Shunting-yard algorithm */
	while (p < end) {
		switch (state) {
		case PARSE_ATOM:
			if (g_ascii_isspace(*p)) {
				state = SKIP_SPACES;
				continue;
			}
			else if (rspamd_expr_is_operation(e, p, end, num_re)) {
				/* Lookahead */
				state = PARSE_OP;
				continue;
			}

			/*
			 * First of all, we check some pre-conditions:
			 * 1) if we have 'and ' or 'or ' or 'not ' strings, they are op
			 * 2) if we have full numeric string, then we check for
			 * the following expression:
			 *  ^\d+\s*[><]$
			 *  and check the operation on stack
			 */
			if ((gulong) (end - p) > sizeof("and ") &&
				(g_ascii_strncasecmp(p, "and ", sizeof("and ") - 1) == 0 ||
				 g_ascii_strncasecmp(p, "not ", sizeof("not ") - 1) == 0)) {
				state = PARSE_OP;
			}
			else if ((gulong) (end - p) > sizeof("or ") &&
					 g_ascii_strncasecmp(p, "or ", sizeof("or ") - 1) == 0) {
				state = PARSE_OP;
			}
			else {
				/*
				 * If we have any comparison or arithmetic operator in the stack, then try
				 * to parse limit or class
				 */
				op = GPOINTER_TO_INT(rspamd_expr_stack_peek(e));

				if (op == OP_MULT || op == OP_MINUS || op == OP_DIVIDE ||
					op == OP_PLUS || (op >= OP_LT && op <= OP_NE) || op == OP_SELECT) {  /* Updated: Include OP_SELECT */
					if (rspamd_regexp_search(num_re,
											 p,
											 end - p,
											 NULL,
											 NULL,
											 FALSE,
											 NULL)) {
						c = p;
						state = PARSE_LIM;
						continue;
					}
					/* New: Check for class names (e.g., "finance", "personal") */
					const char *class_start = p;
					while (p < end && (g_ascii_isalnum(*p) || *p == '_')) {
						p++;
					}
					if (p > class_start) {
						elt.type = ELT_CLASS;
						elt.p.class_name = rspamd_mempool_alloc(pool, p - class_start + 1);
						memcpy(elt.p.class_name, class_start, p - class_start);
						elt.p.class_name[p - class_start] = '\0';
						g_array_append_val(e->expressions, elt);
						rspamd_expr_stack_elt_push(operand_stack,
												   g_node_new(rspamd_expr_dup_elt(pool, &elt)));
						msg_debug_expression("found class: %s; pushed onto operand stack", elt.p.class_name);
						state = SKIP_SPACES;
						continue;
					}
					/* Fallback to atom parsing */
				}

				/* Try to parse atom */
				atom = subr->parse(p, end - p, pool, subr_data, err);
				if (atom == NULL || atom->len == 0) {
					/* We couldn't parse the atom, so go out */
					if (err != NULL && *err == NULL) {
						g_set_error(err,
									rspamd_expr_quark(),
									500,
									"Cannot parse atom: callback function failed"
									" to parse '%.*s'",
									(int) (end - p),
									p);
					}
					goto error_label;
				}

				if (atom->str == NULL) {
					atom->str = p;
				}

				p = p + atom->len;

				/* Push to output */
				elt.type = ELT_ATOM;
				elt.p.atom = atom;
				g_array_append_val(e->expressions, elt);
				rspamd_expr_stack_elt_push(operand_stack,
										   g_node_new(rspamd_expr_dup_elt(pool, &elt)));
				msg_debug_expression("found atom: %*s; pushed onto operand stack (%d size)",
									 (int) atom->len, atom->str, operand_stack->len);
			}
			break;
		case PARSE_LIM:
			if ((g_ascii_isdigit(*p) || *p == '-' || *p == '.') && p < end - 1) {
				p++;
			}
			else {
				if (p == end - 1 && g_ascii_isdigit(*p)) {
					p++;
				}

				if (p - c > 0) {
					elt.type = ELT_LIMIT;
					elt.p.lim = strtod(c, NULL);
					g_array_append_val(e->expressions, elt);
					rspamd_expr_stack_elt_push(operand_stack,
											   g_node_new(rspamd_expr_dup_elt(pool, &elt)));
					msg_debug_expression("found limit: %.1f; pushed onto operand stack (%d size)",
										 elt.p.lim, operand_stack->len);
					c = p;
					state = SKIP_SPACES;
				}
				else {
					g_set_error(err, rspamd_expr_quark(), 400, "Empty number");
					goto error_label;
				}
			}
			break;
		case PARSE_OP:
			op = rspamd_expr_str_to_op(p, end, &p);
			if (op == OP_INVALID) {
				g_set_error(err, rspamd_expr_quark(), 500, "Bad operator %c",
							*p);
				goto error_label;
			}
			else if (op == OP_OBRACE) {
				/*
				 * If the token is a left parenthesis, then push it onto
				 * the stack.
				 */
				rspamd_expr_stack_push(e, GINT_TO_POINTER(op));
				msg_debug_expression("found obrace, pushed to operators stack (%d size)",
									 e->expression_stack->len);
			}
			else if (op == OP_CBRACE) {
				/*
				 * Until the token at the top of the stack is a left
				 * parenthesis, pop operators off the stack onto the
				 * output queue.
				 *
				 * Pop the left parenthesis from the stack,
				 * but not onto the output queue.
				 *
				 * If the stack runs out without finding a left parenthesis,
				 * then there are mismatched parentheses.
				 */
				msg_debug_expression("found cbrace, rewind operators stack (%d size)",
									 e->expression_stack->len);

				do {
					op = GPOINTER_TO_INT(rspamd_expr_stack_pop(e));

					if (op == OP_INVALID) {
						g_set_error(err, rspamd_expr_quark(), 600,
									"Braces mismatch");
						goto error_label;
					}

					unsigned int op_priority = rspamd_expr_logic_priority(op);
					msg_debug_expression("found op: %s; priority = %d",
										 rspamd_expr_op_to_str(op), op_priority);

					if (op != OP_OBRACE) {
						elt.type = ELT_OP;
						elt.p.op.op = op;
						elt.p.op.op_flags = rspamd_expr_op_flags(op);
						elt.p.op.logical_priority = op_priority;
						g_array_append_val(e->expressions, elt);

						if (!rspamd_ast_add_node(e, operand_stack,
												 rspamd_expr_dup_elt(pool, &elt), err)) {
							goto error_label;
						}
					}

				} while (op != OP_OBRACE);
			}
			else {
				/*
				 * While there is an operator token, o2, at the top of
				 * the operator stack, and either:
				 *
				 * - o1 is left-associative and its precedence is less than
				 * or equal to that of o2, or
				 * - o1 is right associative, and has precedence less than
				 * that of o2,
				 *
				 * then pop o2 off the operator stack, onto the output queue;
				 *
				 * push o1 onto the operator stack.
				 */

				for (;;) {
					op_stack = GPOINTER_TO_INT(rspamd_expr_stack_pop(e));

					if (op_stack == OP_INVALID) {
						/* Stack is empty */
						msg_debug_expression("no operations in operators stack");
						break;
					}

					/* We ignore associativity for now */
					unsigned int op_priority = rspamd_expr_logic_priority(op),
								 stack_op_priority = rspamd_expr_logic_priority(op_stack);

					msg_debug_expression("operators stack %d; operands stack: %d; "
										 "process operation '%s'(%d); pop operation '%s'(%d)",
										 e->expression_stack->len,
										 operand_stack->len,
										 rspamd_expr_op_to_str(op), op_priority,
										 rspamd_expr_op_to_str(op_stack), stack_op_priority);

					if (op_stack != OP_OBRACE &&
						op_priority < stack_op_priority) {
						elt.type = ELT_OP;
						elt.p.op.op = op_stack;
						elt.p.op.op_flags = rspamd_expr_op_flags(op_stack);
						elt.p.op.logical_priority = op_priority;

						g_array_append_val(e->expressions, elt);

						if (!rspamd_ast_add_node(e, operand_stack,
												 rspamd_expr_dup_elt(pool, &elt), err)) {
							goto error_label;
						}
					}
					else {
						/* Push op_stack back */
						msg_debug_expression("operators stack %d; operands stack: %d; "
											 "process operation '%s'(%d); push back to stack '%s'(%d)",
											 e->expression_stack->len,
											 operand_stack->len,
											 rspamd_expr_op_to_str(op), op_priority,
											 rspamd_expr_op_to_str(op_stack), stack_op_priority);
						rspamd_expr_stack_push(e, GINT_TO_POINTER(op_stack));
						break;
					}
				}

				/* Push new operator itself */
				msg_debug_expression("operators stack %d; operands stack: %d; "
									 "process operation '%s'; push to stack",
									 e->expression_stack->len,
									 operand_stack->len,
									 rspamd_expr_op_to_str(op));
				rspamd_expr_stack_push(e, GINT_TO_POINTER(op));
			}

			state = SKIP_SPACES;
			break;
		case SKIP_SPACES:
			if (g_ascii_isspace(*p)) {
				p++;
			}
			if (rspamd_expr_is_operation(e, p, end, num_re)) {
				/* Lookahead */
				state = PARSE_OP;
			}
			else {
				state = PARSE_ATOM;
			}
			break;
		}
	}

	/* Now we process the stack and push operators to the output */
	while ((op_stack = GPOINTER_TO_INT(rspamd_expr_stack_pop(e))) != OP_INVALID) {
		msg_debug_expression("operators stack %d; operands stack: %d; "
							 "rewind stack; op: %s",
							 e->expression_stack->len,
							 operand_stack->len,
							 rspamd_expr_op_to_str(op_stack));

		if (op_stack != OP_OBRACE) {
			elt.type = ELT_OP;
			elt.p.op.op = op_stack;
			elt.p.op.op_flags = rspamd_expr_op_flags(op_stack);
			elt.p.op.logical_priority = rspamd_expr_logic_priority(op_stack);

			g_array_append_val(e->expressions, elt);
			if (!rspamd_ast_add_node(e, operand_stack,
									 rspamd_expr_dup_elt(pool, &elt), err)) {
				goto error_label;
			}
		}
		else {
			g_set_error(err, rspamd_expr_quark(), 600,
						"Braces mismatch");
			goto error_label;
		}
	}

	if (operand_stack->len != 1) {
		g_set_error(err, rspamd_expr_quark(), 601,
					"Operators mismatch: %d elts in stack", operand_stack->len);
		goto error_label;
	}

	e->ast = rspamd_expr_stack_elt_pop(operand_stack);
	g_ptr_array_free(operand_stack, TRUE);

	/* Set priorities for branches */
	g_node_traverse(e->ast, G_POST_ORDER, G_TRAVERSE_ALL, -1,
					rspamd_ast_priority_traverse, e);

	/* Now set less expensive branches to be evaluated first */
	g_node_traverse(e->ast, G_POST_ORDER, G_TRAVERSE_NON_LEAVES, -1,
					rspamd_ast_resort_traverse, NULL);

	if (target) {
		*target = e;
		rspamd_mempool_add_destructor(pool,
									  (rspamd_mempool_destruct_t) rspamd_expression_destroy, e);
	}
	else {
		rspamd_expression_destroy(e);
	}

	return TRUE;

error_label:
	if (err && *err) {
		msg_debug_expression("fatal expression parse error: %e", *err);
	}

	while ((tmp = rspamd_expr_stack_elt_pop(operand_stack)) != NULL) {
		g_node_destroy(tmp);
	}

	g_ptr_array_free(operand_stack, TRUE);
	rspamd_expression_destroy(e);

	return FALSE;
}

/*
 *  Node optimizer function: skip nodes that are not relevant
 */
static gboolean
rspamd_ast_node_done(struct rspamd_expression_elt *elt, struct rspamd_expression_result acc)
{
	gboolean ret = FALSE;

	g_assert(elt->type == ELT_OP);

	/* New: Only optimize if result is a double */
	if (acc.type != RSPAMD_RESULT_DOUBLE) {
		return FALSE;
	}

	switch (elt->p.op.op) {
	case OP_NOT:
		ret = TRUE;
		break;
	case OP_AND:
		ret = acc.value.dval == 0;
		break;
	case OP_OR:
		ret = acc.value.dval != 0;
		break;
	default:
		break;
	}

	return ret;
}


static struct rspamd_expression_result  /* Updated: Return structured result */
rspamd_ast_do_unary_op(struct rspamd_expression_elt *elt, struct rspamd_expression_result operand)
{
	struct rspamd_expression_result ret = {.type = RSPAMD_RESULT_DOUBLE};  /* Default to double */
	g_assert(elt->type == ELT_OP);

	/* New: Ensure operand is a double for logical ops */
	if (operand.type != RSPAMD_RESULT_DOUBLE) {
		msg_debug_expression("unary op %s expects numeric operand, got type %d",
							 rspamd_expr_op_to_str(elt->p.op.op), operand.type);
		return operand;  /* Pass through if type mismatch */
	}

	switch (elt->p.op.op) {
	case OP_NOT:
		ret.value.dval = fabs(operand.value.dval) > DBL_EPSILON ? 0.0 : 1.0;
		break;
	default:
		g_assert_not_reached();
	}

	return ret;
}

static struct rspamd_expression_result  /* Updated: Return structured result */
rspamd_ast_do_binary_op(struct rspamd_expression_elt *elt, struct rspamd_expression_result op1, struct rspamd_expression_result op2)
{
	struct rspamd_expression_result ret = {.type = RSPAMD_RESULT_DOUBLE};  /* Default to double */

	g_assert(elt->type == ELT_OP);

	/* New: Ensure operands are doubles for arithmetic/comparison */
	if (op1.type != RSPAMD_RESULT_DOUBLE || op2.type != RSPAMD_RESULT_DOUBLE) {
		msg_debug_expression("binary op %s expects numeric operands, got types %d, %d",
							 rspamd_expr_op_to_str(elt->p.op.op), op1.type, op2.type);
		return op1;  /* Pass through first operand if type mismatch */
	}

	switch (elt->p.op.op) {
	case OP_MINUS:
		ret.value.dval = op1.value.dval - op2.value.dval;
		break;
	case OP_DIVIDE:
		ret.value.dval = op1.value.dval / op2.value.dval;
		break;
	case OP_GE:
		ret.value.dval = op1.value.dval >= op2.value.dval;
		break;
	case OP_GT:
		ret.value.dval = op1.value.dval > op2.value.dval;
		break;
	case OP_LE:
		ret.value.dval = op1.value.dval <= op2.value.dval;
		break;
	case OP_LT:
		ret.value.dval = op1.value.dval < op2.value.dval;
		break;
	case OP_EQ:
		ret.value.dval = op1.value.dval == op2.value.dval;
		break;
	case OP_NE:
		ret.value.dval = op1.value.dval != op2.value.dval;
		break;

	case OP_NOT:
	case OP_PLUS:
	case OP_MULT:
	case OP_AND:
	case OP_OR:
	default:
		g_assert_not_reached();
		break;
	}

	return ret;
}

static struct rspamd_expression_result  /* Updated: Return structured result */
rspamd_ast_do_nary_op(struct rspamd_expression_elt *elt, struct rspamd_expression_result val, struct rspamd_expression_result acc)
{
	struct rspamd_expression_result ret = {.type = RSPAMD_RESULT_DOUBLE};  /* Default to double */

	g_assert(elt->type == ELT_OP);

	/* New: Handle type mismatches */
	if (val.type != RSPAMD_RESULT_DOUBLE || 
		(!isnan(acc.value.dval) && acc.type != RSPAMD_RESULT_DOUBLE)) {
		msg_debug_expression("nary op %s expects numeric operands, got types %d, %d",
							 rspamd_expr_op_to_str(elt->p.op.op), val.type, acc.type);
		return val;  /* Pass through if type mismatch */
	}

	if (isnan(acc.value.dval)) {
		return val;
	}

	switch (elt->p.op.op) {
	case OP_PLUS:
		ret.value.dval = acc.value.dval + val.value.dval;
		break;
	case OP_MULT:
		ret.value.dval = acc.value.dval * val.value.dval;
		break;
	case OP_AND:
		ret.value.dval = (fabs(acc.value.dval) > DBL_EPSILON) && (fabs(val.value.dval) > DBL_EPSILON);
		break;
	case OP_OR:
		ret.value.dval = (fabs(acc.value.dval) > DBL_EPSILON) || (fabs(val.value.dval) > DBL_EPSILON);
		break;
	default:
	case OP_NOT:
	case OP_MINUS:
	case OP_DIVIDE:
	case OP_GE:
	case OP_GT:
	case OP_LE:
	case OP_LT:
	case OP_EQ:
	case OP_NE:
		g_assert_not_reached();
		break;
	}

	return ret;
}

static struct rspamd_expression_result  /* Updated: Return structured result */
rspamd_ast_process_node(struct rspamd_expression *e, GNode *node,
						struct rspamd_expr_process_data *process_data)
{
	struct rspamd_expression_elt *elt;
	GNode *cld;
	struct rspamd_expression_result acc = {.type = RSPAMD_RESULT_DOUBLE, .value.dval = NAN};  /* Updated */
	float t1, t2;
	struct rspamd_expression_result val;
	gboolean calc_ticks = FALSE;
	__attribute__((unused)) const char *op_name = NULL;

	elt = node->data;

	switch (elt->type) {
	case ELT_ATOM:
		if (!(elt->flags & RSPAMD_EXPR_FLAG_PROCESSED)) {
			/*
			 * Check once per 256 evaluations approx
			 */
			calc_ticks = (rspamd_random_uint64_fast() & 0xff) == 0xff;
			if (calc_ticks) {
				t1 = rspamd_get_ticks(TRUE);
			}

			/* New: Assume process_closure returns a double; extend subr if needed */
			elt->value.type = RSPAMD_RESULT_DOUBLE;
			elt->value.value.dval = process_data->process_closure(process_data->ud, elt->p.atom);

			if (fabs(elt->value.value.dval) > DBL_EPSILON) {
				elt->p.atom->hits++;

				if (process_data->trace) {
					g_ptr_array_add(process_data->trace, elt->p.atom);
				}
			}

			if (calc_ticks) {
				t2 = rspamd_get_ticks(TRUE);
				rspamd_set_counter_ema(&elt->p.atom->exec_time, (t2 - t1), 0.5f);
			}

			elt->flags |= RSPAMD_EXPR_FLAG_PROCESSED;
		}

		acc = elt->value;
		msg_debug_expression_verbose("atom: elt=%s; acc=%.1f", elt->p.atom->str, acc.value.dval);
		break;
	case ELT_LIMIT:
		acc.type = RSPAMD_RESULT_DOUBLE;
		acc.value.dval = elt->p.lim;
		msg_debug_expression_verbose("limit: lim=%.1f; acc=%.1f;", elt->p.lim, acc.value.dval);
		break;
	case ELT_CLASS:  /* New: Handle class elements */
		acc.type = RSPAMD_RESULT_STRING;
		acc.value.sval = elt->p.class_name;
		msg_debug_expression_verbose("class: %s", elt->p.class_name);
		break;
	case ELT_OP:
		g_assert(node->children != NULL);
#ifdef DEBUG_EXPRESSIONS
		op_name = rspamd_expr_op_to_str(elt->p.op.op);
#endif

		/* New: Handle OP_SELECT (ternary operator for multiclass) */
		if (elt->p.op.op == OP_SELECT) {
			GNode *cond = node->children;
			GNode *true_val = cond->next;
			GNode *false_val = true_val->next;
			g_assert(false_val != NULL);

			struct rspamd_expression_result cond_res = rspamd_ast_process_node(e, cond, process_data);
			if (cond_res.type == RSPAMD_RESULT_DOUBLE && cond_res.value.dval > DBL_EPSILON) {
				acc = rspamd_ast_process_node(e, true_val, process_data);
			}
			else {
				acc = rspamd_ast_process_node(e, false_val, process_data);
			}
			msg_debug_expression_verbose("select op: %s; result type=%d", op_name, acc.type);
		}
		else if (elt->p.op.op_flags & RSPAMD_EXPRESSION_NARY) {
			msg_debug_expression_verbose("proceed nary operation %s", op_name);
			/* Proceed all ops in chain */
			DL_FOREACH(node->children, cld)
			{
				val = rspamd_ast_process_node(e, cld, process_data);
				msg_debug_expression_verbose("before op: op=%s; acc=%.1f; val = %.2f", op_name,
											 acc.value.dval, val.value.dval);
				acc = rspamd_ast_do_nary_op(elt, val, acc);
				msg_debug_expression_verbose("after op: op=%s; acc=%.1f; val = %.2f", op_name,
											 acc.value.dval, val.value.dval);

				/* Check if we need to process further */
				if (!(process_data->flags & RSPAMD_EXPRESSION_FLAG_NOOPT)) {
					if (rspamd_ast_node_done(elt, acc)) {
						msg_debug_expression_verbose("optimizer: done");
						return acc;
					}
				}
			}
		}
		else if (elt->p.op.op_flags & RSPAMD_EXPRESSION_BINARY) {
			GNode *c1 = node->children, *c2;

			c2 = c1->next;
			g_assert(c2->next == NULL);
			struct rspamd_expression_result val1, val2;

			msg_debug_expression_verbose("proceed binary operation %s",
										 op_name);
			val1 = rspamd_ast_process_node(e, c1, process_data);
			val2 = rspamd_ast_process_node(e, c2, process_data);

			msg_debug_expression_verbose("before op: op=%s; op1 = %.1f, op2 = %.1f",
										 op_name, val1.value.dval, val2.value.dval);
			acc = rspamd_ast_do_binary_op(elt, val1, val2);
			msg_debug_expression_verbose("after op: op=%s; res=%.1f",
										 op_name, acc.value.dval);
		}
		else if (elt->p.op.op_flags & RSPAMD_EXPRESSION_UNARY) {
			GNode *c1 = node->children;

			g_assert(c1->next == NULL);

			msg_debug_expression_verbose("proceed unary operation %s",
										 op_name);
			val = rspamd_ast_process_node(e, c1, process_data);

			msg_debug_expression_verbose("before op: op=%s; op1 = %.1f",
										 op_name, val.value.dval);
			acc = rspamd_ast_do_unary_op(elt, val);
			msg_debug_expression_verbose("after op: op=%s; res=%.1f",
										 op_name, acc.value.dval);
		}
		break;
	}

	return acc;
}

static gboolean
rspamd_ast_cleanup_traverse(GNode *n, gpointer d)
{
	struct rspamd_expression_elt *elt = n->data;

	/* Updated: Reset to default double type */
	elt->value.type = RSPAMD_RESULT_DOUBLE;
	elt->value.value.dval = 0;
	elt->flags = 0;

	return FALSE;
}

struct rspamd_expression_result  /* Updated: Return structured result */
rspamd_process_expression_closure(struct rspamd_expression *expr,
								  rspamd_expression_process_cb cb,
								  int flags,
								  gpointer runtime_ud,
								  GPtrArray **track)
{
	struct rspamd_expr_process_data pd;
	struct rspamd_expression_result ret;  /* Updated */

	g_assert(expr != NULL);
	/* Ensure that stack is empty at this point */
	g_assert(expr->expression_stack->len == 0);

	expr->evals++;

	memset(&pd, 0, sizeof(pd));
	pd.process_closure = cb;
	pd.flags = flags;
	pd.ud = runtime_ud;

	if (track) {
		pd.trace = g_ptr_array_sized_new(32);
		*track = pd.trace;
	}

	ret = rspamd_ast_process_node(expr, expr->ast, &pd);

	/* Cleanup */
	g_node_traverse(expr->ast, G_IN_ORDER, G_TRAVERSE_ALL, -1,
					rspamd_ast_cleanup_traverse, NULL);

	/* Check if we need to resort */
	if (expr->evals % expr->next_resort == 0) {
		expr->next_resort = ottery_rand_range(MAX_RESORT_EVALS) +
							MIN_RESORT_EVALS;
		/* Set priorities for branches */
		g_node_traverse(expr->ast, G_POST_ORDER, G_TRAVERSE_ALL, -1,
						rspamd_ast_priority_traverse, expr);

		/* Now set less expensive branches to be evaluated first */
		g_node_traverse(expr->ast, G_POST_ORDER, G_TRAVERSE_NON_LEAVES, -1,
						rspamd_ast_resort_traverse, NULL);
	}

	return ret;
}

struct rspamd_expression_result  /* Updated: Return structured result */
rspamd_process_expression_track(struct rspamd_expression *expr,
								int flags,
								gpointer runtime_ud,
								GPtrArray **track)
{
	return rspamd_process_expression_closure(expr,
											 expr->subr->process, flags, runtime_ud, track);
}

struct rspamd_expression_result  /* Updated: Return structured result */
rspamd_process_expression(struct rspamd_expression *expr,
						  int flags,
						  gpointer runtime_ud)
{
	return rspamd_process_expression_closure(expr,
											 expr->subr->process, flags, runtime_ud, NULL);
}

static gboolean
rspamd_ast_string_traverse(GNode *n, gpointer d)
{
	GString *res = d;
	int cnt;
	GNode *cur;
	struct rspamd_expression_elt *elt = n->data;
	const char *op_str = NULL;

	if (elt->type == ELT_ATOM) {
		rspamd_printf_gstring(res, "(%*s)",
							  (int) elt->p.atom->len, elt->p.atom->str);
	}
	else if (elt->type == ELT_LIMIT) {
		if (elt->p.lim == (double) (int64_t) elt->p.lim) {
			rspamd_printf_gstring(res, "%L", (int64_t) elt->p.lim);
		}
		else {
			rspamd_printf_gstring(res, "%f", elt->p.lim);
		}
	}
	else if (elt->type == ELT_CLASS) {  /* New: Stringify class elements */
		rspamd_printf_gstring(res, "%s", elt->p.class_name);
	}
	else {
		op_str = rspamd_expr_op_to_str(elt->p.op.op);
		g_string_append(res, op_str);

		if (n->children) {
			LL_COUNT(n->children, cur, cnt);

			if (cnt > 2) {
				/* Print n-ary of the operator */
				g_string_append_printf(res, "(%d)", cnt);
			}
		}
	}

	g_string_append_c(res, ' ');

	return FALSE;
}

GString *
rspamd_expression_tostring(struct rspamd_expression *expr)
{
	GString *res;

	g_assert(expr != NULL);

	res = g_string_new(NULL);
	g_node_traverse(expr->ast, G_POST_ORDER, G_TRAVERSE_ALL, -1,
					rspamd_ast_string_traverse, res);

	/* Last space */
	if (res->len > 0) {
		g_string_erase(res, res->len - 1, 1);
	}

	return res;
}

struct atom_foreach_cbdata {
	rspamd_expression_atom_foreach_cb cb;
	gpointer cbdata;
};

static gboolean
rspamd_ast_atom_traverse(GNode *n, gpointer d)
{
	struct atom_foreach_cbdata *data = d;
	struct rspamd_expression_elt *elt = n->data;
	rspamd_ftok_t tok;

	if (elt->type == ELT_ATOM) {
		tok.begin = elt->p.atom->str;
		tok.len = elt->p.atom->len;

		data->cb(&tok, data->cbdata);
	}

	return FALSE;
}

void rspamd_expression_atom_foreach(struct rspamd_expression *expr,
									rspamd_expression_atom_foreach_cb cb, gpointer cbdata)
{
	struct atom_foreach_cbdata data;

	g_assert(expr != NULL);

	data.cb = cb;
	data.cbdata = cbdata;
	g_node_traverse(expr->ast, G_POST_ORDER, G_TRAVERSE_ALL, -1,
					rspamd_ast_atom_traverse, &data);
}

gboolean
rspamd_expression_node_is_op(GNode *node, enum rspamd_expression_op op)
{
	struct rspamd_expression_elt *elt;

	g_assert(node != NULL);

	elt = node->data;

	if (elt->type == ELT_OP && elt->p.op.op == op) {
		return TRUE;
	}

	return FALSE;
}