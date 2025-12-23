.class public final Lorg/jeasy/rules/core/DefaultRulesEngine;
.super Lorg/jeasy/rules/core/AbstractRulesEngine;
.source "SourceFile"


# static fields
.field private static final LOGGER:Lorg/slf4j/Logger;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-class v0, Lorg/jeasy/rules/core/DefaultRulesEngine;

    invoke-static {v0}, Lorg/slf4j/LoggerFactory;->getLogger(Ljava/lang/Class;)Lorg/slf4j/Logger;

    move-result-object v0

    sput-object v0, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Lorg/jeasy/rules/core/AbstractRulesEngine;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yx7;)V
    .locals 0

    invoke-direct {p0, p1}, Lorg/jeasy/rules/core/AbstractRulesEngine;-><init>(Llyiahf/vczjk/yx7;)V

    return-void
.end method

.method public static synthetic OooO00o(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->lambda$triggerListenersAfterRules$7(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/xx7;)V

    return-void
.end method

.method public static synthetic OooO0O0(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->lambda$triggerListenersBeforeRules$6(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/xx7;)V

    return-void
.end method

.method public static synthetic OooO0OO(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, p2, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->lambda$triggerListenersOnEvaluationError$5(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;Llyiahf/vczjk/ox7;)V

    return-void
.end method

.method public static synthetic OooO0Oo(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)Z
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->lambda$triggerListenersBeforeEvaluate$3(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/ox7;)Z

    move-result p0

    return p0
.end method

.method public static synthetic OooO0o(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Z)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, p2, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->lambda$triggerListenersAfterEvaluate$4(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;ZLlyiahf/vczjk/ox7;)V

    return-void
.end method

.method public static synthetic OooO0o0(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->lambda$triggerListenersBeforeExecute$2(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/ox7;)V

    return-void
.end method

.method public static synthetic OooO0oO(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->lambda$triggerListenersOnSuccess$1(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/ox7;)V

    return-void
.end method

.method public static synthetic OooO0oo(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, p2, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->lambda$triggerListenersOnFailure$0(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;Llyiahf/vczjk/ox7;)V

    return-void
.end method

.method private doCheck(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)Ljava/util/Map;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/wx7;",
            "Llyiahf/vczjk/gv2;",
            ")",
            "Ljava/util/Map<",
            "Llyiahf/vczjk/nw7;",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation

    sget-object v0, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string v1, "Checking rules"

    invoke-interface {v0, v1}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;)V

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/wx7;->OooOOO0:Ljava/util/TreeSet;

    invoke-virtual {p1}, Ljava/util/TreeSet;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/nw7;

    invoke-direct {p0, v1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->shouldBeEvaluated(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v1, p2}, Llyiahf/vczjk/nw7;->evaluate(Llyiahf/vczjk/gv2;)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_1
    return-object v0
.end method

.method private static synthetic lambda$triggerListenersAfterEvaluate$4(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;ZLlyiahf/vczjk/ox7;)V
    .locals 0

    invoke-interface {p3}, Llyiahf/vczjk/ox7;->OooO0o0()V

    return-void
.end method

.method private static synthetic lambda$triggerListenersAfterRules$7(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/xx7;)V
    .locals 0

    invoke-interface {p2}, Llyiahf/vczjk/xx7;->OooO0O0()V

    return-void
.end method

.method private static synthetic lambda$triggerListenersBeforeEvaluate$3(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/ox7;)Z
    .locals 0

    invoke-interface {p2}, Llyiahf/vczjk/ox7;->OooO00o()Z

    move-result p0

    return p0
.end method

.method private static synthetic lambda$triggerListenersBeforeExecute$2(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/ox7;)V
    .locals 0

    invoke-interface {p2}, Llyiahf/vczjk/ox7;->OooO0Oo()V

    return-void
.end method

.method private static synthetic lambda$triggerListenersBeforeRules$6(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/xx7;)V
    .locals 0

    invoke-interface {p2}, Llyiahf/vczjk/xx7;->OooO00o()V

    return-void
.end method

.method private static synthetic lambda$triggerListenersOnEvaluationError$5(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;Llyiahf/vczjk/ox7;)V
    .locals 0

    invoke-interface {p3}, Llyiahf/vczjk/ox7;->OooO0OO()V

    return-void
.end method

.method private static synthetic lambda$triggerListenersOnFailure$0(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;Llyiahf/vczjk/ox7;)V
    .locals 0

    invoke-interface {p3}, Llyiahf/vczjk/ox7;->OooO0O0()V

    return-void
.end method

.method private static synthetic lambda$triggerListenersOnSuccess$1(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Llyiahf/vczjk/ox7;)V
    .locals 0

    invoke-interface {p2}, Llyiahf/vczjk/ox7;->onSuccess()V

    return-void
.end method

.method private log(Llyiahf/vczjk/gv2;)V
    .locals 3

    sget-object v0, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string v1, "Known facts:"

    invoke-interface {v0, v1}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/gv2;->OooOOO0:Ljava/util/HashSet;

    invoke-virtual {p1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dv2;

    sget-object v1, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string v2, "{}"

    invoke-interface {v1, v2, v0}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method private log(Llyiahf/vczjk/wx7;)V
    .locals 4

    sget-object v0, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string v1, "Registered rules:"

    invoke-interface {v0, v1}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/wx7;->OooOOO0:Ljava/util/TreeSet;

    invoke-virtual {p1}, Ljava/util/TreeSet;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nw7;

    sget-object v1, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    invoke-interface {v0}, Llyiahf/vczjk/nw7;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-interface {v0}, Llyiahf/vczjk/nw7;->getDescription()Ljava/lang/String;

    move-result-object v3

    invoke-interface {v0}, Llyiahf/vczjk/nw7;->getPriority()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {v2, v3, v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v2, "Rule { name = \'{}\', description = \'{}\', priority = \'{}\'}"

    invoke-interface {v1, v2, v0}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method private logEngineParameters()V
    .locals 3

    sget-object v0, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string v1, "{}"

    iget-object v2, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->parameters:Llyiahf/vczjk/yx7;

    invoke-interface {v0, v1, v2}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;Ljava/lang/Object;)V

    return-void
.end method

.method private shouldBeEvaluated(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)Z
    .locals 0

    invoke-direct {p0, p1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersBeforeEvaluate(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)Z

    move-result p1

    return p1
.end method

.method private triggerListenersAfterEvaluate(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Z)V
    .locals 2

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/p32;

    invoke-direct {v1, p1, p2, p3}, Llyiahf/vczjk/p32;-><init>(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Z)V

    invoke-interface {v0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    return-void
.end method

.method private triggerListenersAfterRules(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V
    .locals 3

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->rulesEngineListeners:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/l32;

    const/4 v2, 0x0

    invoke-direct {v1, p1, p2, v2}, Llyiahf/vczjk/l32;-><init>(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;I)V

    invoke-interface {v0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    return-void
.end method

.method private triggerListenersBeforeEvaluate(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)Z
    .locals 3

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/o32;

    const/4 v2, 0x0

    invoke-direct {v1, v2, p1, p2}, Llyiahf/vczjk/o32;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-interface {v0, v1}, Ljava/util/stream/Stream;->allMatch(Ljava/util/function/Predicate;)Z

    move-result p1

    return p1
.end method

.method private triggerListenersBeforeExecute(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)V
    .locals 3

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/n32;

    const/4 v2, 0x0

    invoke-direct {v1, p1, p2, v2}, Llyiahf/vczjk/n32;-><init>(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;I)V

    invoke-interface {v0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    return-void
.end method

.method private triggerListenersBeforeRules(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V
    .locals 3

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->rulesEngineListeners:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/l32;

    const/4 v2, 0x1

    invoke-direct {v1, p1, p2, v2}, Llyiahf/vczjk/l32;-><init>(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;I)V

    invoke-interface {v0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    return-void
.end method

.method private triggerListenersOnEvaluationError(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;)V
    .locals 3

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/m32;

    const/4 v2, 0x0

    invoke-direct {v1, p1, p2, p3, v2}, Llyiahf/vczjk/m32;-><init>(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;I)V

    invoke-interface {v0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    return-void
.end method

.method private triggerListenersOnFailure(Llyiahf/vczjk/nw7;Ljava/lang/Exception;Llyiahf/vczjk/gv2;)V
    .locals 3

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/m32;

    const/4 v2, 0x1

    invoke-direct {v1, p1, p3, p2, v2}, Llyiahf/vczjk/m32;-><init>(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;I)V

    invoke-interface {v0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    return-void
.end method

.method private triggerListenersOnSuccess(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)V
    .locals 3

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/n32;

    const/4 v2, 0x1

    invoke-direct {v1, p1, p2, v2}, Llyiahf/vczjk/n32;-><init>(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;I)V

    invoke-interface {v0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    return-void
.end method


# virtual methods
.method public check(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)Ljava/util/Map;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/wx7;",
            "Llyiahf/vczjk/gv2;",
            ")",
            "Ljava/util/Map<",
            "Llyiahf/vczjk/nw7;",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation

    invoke-direct {p0, p1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersBeforeRules(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V

    invoke-direct {p0, p1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->doCheck(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)Ljava/util/Map;

    move-result-object v0

    invoke-direct {p0, p1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersAfterRules(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V

    return-object v0
.end method

.method public doFire(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V
    .locals 8

    const-string v0, "Rule \'"

    iget-object v1, p1, Llyiahf/vczjk/wx7;->OooOOO0:Ljava/util/TreeSet;

    invoke-virtual {v1}, Ljava/util/TreeSet;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object p1, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string p2, "No rules registered! Nothing to apply"

    invoke-interface {p1, p2}, Lorg/slf4j/Logger;->warn(Ljava/lang/String;)V

    return-void

    :cond_0
    invoke-direct {p0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->logEngineParameters()V

    invoke-direct {p0, p1}, Lorg/jeasy/rules/core/DefaultRulesEngine;->log(Llyiahf/vczjk/wx7;)V

    invoke-direct {p0, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->log(Llyiahf/vczjk/gv2;)V

    sget-object v1, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string v2, "Rules evaluation started"

    invoke-interface {v1, v2}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/wx7;->OooOOO0:Ljava/util/TreeSet;

    invoke-virtual {p1}, Ljava/util/TreeSet;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/nw7;

    invoke-interface {v1}, Llyiahf/vczjk/nw7;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-interface {v1}, Llyiahf/vczjk/nw7;->getPriority()I

    move-result v3

    iget-object v4, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->parameters:Llyiahf/vczjk/yx7;

    iget v4, v4, Llyiahf/vczjk/yx7;->OooO00o:I

    if-le v3, v4, :cond_1

    sget-object p1, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {p2, v2, v0}, [Ljava/lang/Object;

    move-result-object p2

    const-string v0, "Rule priority threshold ({}) exceeded at rule \'{}\' with priority={}, next rules will be skipped"

    invoke-interface {p1, v0, p2}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;[Ljava/lang/Object;)V

    goto/16 :goto_2

    :cond_1
    invoke-direct {p0, v1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->shouldBeEvaluated(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)Z

    move-result v3

    if-nez v3, :cond_2

    sget-object v1, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string v3, "Rule \'{}\' has been skipped before being evaluated"

    invoke-interface {v1, v3, v2}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    const/4 v3, 0x0

    :try_start_0
    invoke-interface {v1, p2}, Llyiahf/vczjk/nw7;->evaluate(Llyiahf/vczjk/gv2;)Z

    move-result v4
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception v4

    sget-object v5, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v7, "\' evaluated with error"

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-interface {v5, v6, v4}, Lorg/slf4j/Logger;->error(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-direct {p0, v1, p2, v4}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersOnEvaluationError(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Ljava/lang/Exception;)V

    iget-object v4, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->parameters:Llyiahf/vczjk/yx7;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move v4, v3

    :goto_1
    if-eqz v4, :cond_3

    sget-object v3, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string v4, "Rule \'{}\' triggered"

    invoke-interface {v3, v4, v2}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;Ljava/lang/Object;)V

    const/4 v4, 0x1

    invoke-direct {p0, v1, p2, v4}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersAfterEvaluate(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Z)V

    :try_start_1
    invoke-direct {p0, v1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersBeforeExecute(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)V

    invoke-interface {v1, p2}, Llyiahf/vczjk/nw7;->execute(Llyiahf/vczjk/gv2;)V

    const-string v4, "Rule \'{}\' performed successfully"

    invoke-interface {v3, v4, v2}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-direct {p0, v1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersOnSuccess(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;)V

    iget-object v3, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->parameters:Llyiahf/vczjk/yx7;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto/16 :goto_0

    :catch_1
    move-exception v3

    sget-object v4, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "\' performed with error"

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-interface {v4, v2, v3}, Lorg/slf4j/Logger;->error(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-direct {p0, v1, v3, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersOnFailure(Llyiahf/vczjk/nw7;Ljava/lang/Exception;Llyiahf/vczjk/gv2;)V

    iget-object v1, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->parameters:Llyiahf/vczjk/yx7;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto/16 :goto_0

    :cond_3
    sget-object v4, Lorg/jeasy/rules/core/DefaultRulesEngine;->LOGGER:Lorg/slf4j/Logger;

    const-string v5, "Rule \'{}\' has been evaluated to false, it has not been executed"

    invoke-interface {v4, v5, v2}, Lorg/slf4j/Logger;->debug(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-direct {p0, v1, p2, v3}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersAfterEvaluate(Llyiahf/vczjk/nw7;Llyiahf/vczjk/gv2;Z)V

    iget-object v1, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->parameters:Llyiahf/vczjk/yx7;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto/16 :goto_0

    :cond_4
    :goto_2
    return-void
.end method

.method public fire(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersBeforeRules(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V

    invoke-virtual {p0, p1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->doFire(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V

    invoke-direct {p0, p1, p2}, Lorg/jeasy/rules/core/DefaultRulesEngine;->triggerListenersAfterRules(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V

    return-void
.end method
