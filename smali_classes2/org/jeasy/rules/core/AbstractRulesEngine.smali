.class public abstract Lorg/jeasy/rules/core/AbstractRulesEngine;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field parameters:Llyiahf/vczjk/yx7;

.field ruleListeners:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/ox7;",
            ">;"
        }
    .end annotation
.end field

.field rulesEngineListeners:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/xx7;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/yx7;

    invoke-direct {v0}, Llyiahf/vczjk/yx7;-><init>()V

    invoke-direct {p0, v0}, Lorg/jeasy/rules/core/AbstractRulesEngine;-><init>(Llyiahf/vczjk/yx7;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yx7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->parameters:Llyiahf/vczjk/yx7;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->rulesEngineListeners:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public check(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)Ljava/util/Map;
    .locals 0

    sget-object p1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    return-object p1
.end method

.method public abstract fire(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V
.end method

.method public getParameters()Llyiahf/vczjk/yx7;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yx7;

    iget-object v1, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->parameters:Llyiahf/vczjk/yx7;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, v1, Llyiahf/vczjk/yx7;->OooO00o:I

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput v1, v0, Llyiahf/vczjk/yx7;->OooO00o:I

    return-object v0
.end method

.method public getRuleListeners()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Llyiahf/vczjk/ox7;",
            ">;"
        }
    .end annotation

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public getRulesEngineListeners()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Llyiahf/vczjk/xx7;",
            ">;"
        }
    .end annotation

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->rulesEngineListeners:Ljava/util/List;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public registerRuleListener(Llyiahf/vczjk/ox7;)V
    .locals 1

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public registerRuleListeners(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Llyiahf/vczjk/ox7;",
            ">;)V"
        }
    .end annotation

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->ruleListeners:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    return-void
.end method

.method public registerRulesEngineListener(Llyiahf/vczjk/xx7;)V
    .locals 1

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->rulesEngineListeners:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public registerRulesEngineListeners(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Llyiahf/vczjk/xx7;",
            ">;)V"
        }
    .end annotation

    iget-object v0, p0, Lorg/jeasy/rules/core/AbstractRulesEngine;->rulesEngineListeners:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    return-void
.end method
