.class public final Llyiahf/vczjk/kl;
.super Llyiahf/vczjk/ml;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Llyiahf/vczjk/gf4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gf4;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0, p2}, Llyiahf/vczjk/ml;-><init>(Llyiahf/vczjk/oe3;)V

    iput-object p1, p0, Llyiahf/vczjk/kl;->OooO0OO:Llyiahf/vczjk/gf4;

    return-void
.end method

.method public static OooO0OO(Llyiahf/vczjk/dk3;Llyiahf/vczjk/gf4;)Ljava/lang/Object;
    .locals 3

    iget-object p0, p0, Llyiahf/vczjk/dk3;->OooO0o:Ljava/lang/Object;

    check-cast p0, Ljava/lang/Iterable;

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/rs;->Oooo0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v2

    goto :goto_0

    :cond_1
    move-object v2, v1

    :goto_0
    invoke-static {v2, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_1

    :cond_2
    move-object v0, v1

    :goto_1
    const-string p0, "<this>"

    invoke-static {p1, p0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/gf4;->OooO0OO(Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_3

    const-string p0, "null cannot be cast to non-null type T of kotlin.reflect.KClasses.safeCast"

    invoke-static {v0, p0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :cond_3
    return-object v1
.end method


# virtual methods
.method public final OooO00o(Ljava/util/ArrayList;)V
    .locals 4

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/dk3;

    iget-object v2, v2, Llyiahf/vczjk/dk3;->OooO0OO:Llyiahf/vczjk/yx8;

    if-eqz v2, :cond_0

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/ml;->OooO0O0:Ljava/util/LinkedHashSet;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_2
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/dk3;

    iget-object v3, p0, Llyiahf/vczjk/kl;->OooO0OO:Llyiahf/vczjk/gf4;

    invoke-static {v2, v3}, Llyiahf/vczjk/kl;->OooO0OO(Llyiahf/vczjk/dk3;Llyiahf/vczjk/gf4;)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    invoke-static {v1}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/util/Collection;

    invoke-interface {p1, v0}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/dk3;)Z
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/dk3;->OooO0OO:Llyiahf/vczjk/yx8;

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/kl;->OooO0OO:Llyiahf/vczjk/gf4;

    invoke-static {p1, v0}, Llyiahf/vczjk/kl;->OooO0OO(Llyiahf/vczjk/dk3;Llyiahf/vczjk/gf4;)Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method
