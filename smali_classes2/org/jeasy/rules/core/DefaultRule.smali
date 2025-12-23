.class Lorg/jeasy/rules/core/DefaultRule;
.super Lorg/jeasy/rules/core/BasicRule;
.source "SourceFile"


# instance fields
.field private final actions:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/oO0Oo;",
            ">;"
        }
    .end annotation
.end field

.field private final condition:Llyiahf/vczjk/qh1;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/qh1;Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "I",
            "Llyiahf/vczjk/qh1;",
            "Ljava/util/List<",
            "Llyiahf/vczjk/oO0Oo;",
            ">;)V"
        }
    .end annotation

    invoke-direct {p0, p1, p2, p3}, Lorg/jeasy/rules/core/BasicRule;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    iput-object p4, p0, Lorg/jeasy/rules/core/DefaultRule;->condition:Llyiahf/vczjk/qh1;

    iput-object p5, p0, Lorg/jeasy/rules/core/DefaultRule;->actions:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public evaluate(Llyiahf/vczjk/gv2;)Z
    .locals 1

    iget-object v0, p0, Lorg/jeasy/rules/core/DefaultRule;->condition:Llyiahf/vczjk/qh1;

    invoke-interface {v0, p1}, Llyiahf/vczjk/qh1;->evaluate(Llyiahf/vczjk/gv2;)Z

    move-result p1

    return p1
.end method

.method public execute(Llyiahf/vczjk/gv2;)V
    .locals 2

    iget-object v0, p0, Lorg/jeasy/rules/core/DefaultRule;->actions:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/oO0Oo;

    check-cast v1, Llyiahf/vczjk/p95;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/p95;->OooO00o(Llyiahf/vczjk/gv2;)V

    goto :goto_0

    :cond_0
    return-void
.end method
