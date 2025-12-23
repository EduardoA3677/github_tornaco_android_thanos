.class public final Llyiahf/vczjk/i41;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/or1;
.implements Ljava/io/Serializable;


# instance fields
.field private final element:Llyiahf/vczjk/mr1;

.field private final left:Llyiahf/vczjk/or1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)V
    .locals 1

    const-string v0, "left"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "element"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/i41;->left:Llyiahf/vczjk/or1;

    iput-object p1, p0, Llyiahf/vczjk/i41;->element:Llyiahf/vczjk/mr1;

    return-void
.end method

.method private final writeReplace()Ljava/lang/Object;
    .locals 6

    invoke-virtual {p0}, Llyiahf/vczjk/i41;->OooO00o()I

    move-result v0

    new-array v1, v0, [Llyiahf/vczjk/or1;

    new-instance v2, Llyiahf/vczjk/fl7;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    new-instance v4, Llyiahf/vczjk/e2;

    const/4 v5, 0x7

    invoke-direct {v4, v5, v1, v2}, Llyiahf/vczjk/e2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p0, v3, v4}, Llyiahf/vczjk/i41;->o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    iget v2, v2, Llyiahf/vczjk/fl7;->element:I

    if-ne v2, v0, :cond_0

    new-instance v0, Llyiahf/vczjk/h41;

    invoke-direct {v0, v1}, Llyiahf/vczjk/h41;-><init>([Llyiahf/vczjk/or1;)V

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Check failed."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public final OooO00o()I
    .locals 3

    const/4 v0, 0x2

    move-object v1, p0

    :goto_0
    iget-object v1, v1, Llyiahf/vczjk/i41;->left:Llyiahf/vczjk/or1;

    instance-of v2, v1, Llyiahf/vczjk/i41;

    if-eqz v2, :cond_0

    check-cast v1, Llyiahf/vczjk/i41;

    goto :goto_1

    :cond_0
    const/4 v1, 0x0

    :goto_1
    if-nez v1, :cond_1

    return v0

    :cond_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0
.end method

.method public final OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;
    .locals 2

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/v1;

    const/16 v1, 0x15

    invoke-direct {v0, v1}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-interface {p1, p0, v0}, Llyiahf/vczjk/or1;->o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/or1;

    return-object p1
.end method

.method public final OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;
    .locals 2

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v0, p0

    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/i41;->element:Llyiahf/vczjk/mr1;

    invoke-interface {v1, p1}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v1

    if-eqz v1, :cond_0

    return-object v1

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/i41;->left:Llyiahf/vczjk/or1;

    instance-of v1, v0, Llyiahf/vczjk/i41;

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/i41;

    goto :goto_0

    :cond_1
    invoke-interface {v0, p1}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;
    .locals 2

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/i41;->element:Llyiahf/vczjk/mr1;

    invoke-interface {v0, p1}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/i41;->left:Llyiahf/vczjk/or1;

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/i41;->left:Llyiahf/vczjk/or1;

    invoke-interface {v0, p1}, Llyiahf/vczjk/or1;->OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/i41;->left:Llyiahf/vczjk/or1;

    if-ne p1, v0, :cond_1

    return-object p0

    :cond_1
    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    if-ne p1, v0, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/i41;->element:Llyiahf/vczjk/mr1;

    return-object p1

    :cond_2
    new-instance v0, Llyiahf/vczjk/i41;

    iget-object v1, p0, Llyiahf/vczjk/i41;->element:Llyiahf/vczjk/mr1;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/i41;-><init>(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)V

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    if-eq p0, p1, :cond_3

    instance-of v0, p1, Llyiahf/vczjk/i41;

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    check-cast p1, Llyiahf/vczjk/i41;

    invoke-virtual {p1}, Llyiahf/vczjk/i41;->OooO00o()I

    move-result v0

    invoke-virtual {p0}, Llyiahf/vczjk/i41;->OooO00o()I

    move-result v2

    if-ne v0, v2, :cond_2

    move-object v0, p0

    :goto_0
    iget-object v2, v0, Llyiahf/vczjk/i41;->element:Llyiahf/vczjk/mr1;

    invoke-interface {v2}, Llyiahf/vczjk/mr1;->getKey()Llyiahf/vczjk/nr1;

    move-result-object v3

    invoke-virtual {p1, v3}, Llyiahf/vczjk/i41;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v3

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_0

    move p1, v1

    goto :goto_1

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/i41;->left:Llyiahf/vczjk/or1;

    instance-of v2, v0, Llyiahf/vczjk/i41;

    if-eqz v2, :cond_1

    check-cast v0, Llyiahf/vczjk/i41;

    goto :goto_0

    :cond_1
    const-string v2, "null cannot be cast to non-null type kotlin.coroutines.CoroutineContext.Element"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/mr1;

    invoke-interface {v0}, Llyiahf/vczjk/mr1;->getKey()Llyiahf/vczjk/nr1;

    move-result-object v2

    invoke-virtual {p1, v2}, Llyiahf/vczjk/i41;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    :goto_1
    if-eqz p1, :cond_2

    goto :goto_2

    :cond_2
    return v1

    :cond_3
    :goto_2
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/i41;->left:Llyiahf/vczjk/or1;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/i41;->element:Llyiahf/vczjk/mr1;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i41;->left:Llyiahf/vczjk/or1;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/or1;->o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/i41;->element:Llyiahf/vczjk/mr1;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "["

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/v1;

    const/16 v2, 0x11

    invoke-direct {v1, v2}, Llyiahf/vczjk/v1;-><init>(I)V

    const-string v2, ""

    invoke-virtual {p0, v2, v1}, Llyiahf/vczjk/i41;->o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    const/16 v2, 0x5d

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/ii5;->OooOO0O(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
