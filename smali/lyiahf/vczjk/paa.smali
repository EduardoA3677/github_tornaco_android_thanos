.class public final Llyiahf/vczjk/paa;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/mr1;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/jz1;

.field public final OooOOO0:Llyiahf/vczjk/paa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/paa;Llyiahf/vczjk/jz1;)V
    .locals 1

    const-string v0, "instance"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/paa;->OooOOO0:Llyiahf/vczjk/paa;

    iput-object p2, p0, Llyiahf/vczjk/paa;->OooOOO:Llyiahf/vczjk/jz1;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/jz1;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/paa;->OooOOO:Llyiahf/vczjk/jz1;

    if-eq v0, p1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/paa;->OooOOO0:Llyiahf/vczjk/paa;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/paa;->OooO00o(Llyiahf/vczjk/jz1;)V

    :cond_0
    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Calling updateData inside updateData on the same DataStore instance is not supported\nsince updates made in the parent updateData call will not be visible to the nested\nupdateData call. See https://issuetracker.google.com/issues/241760537 for details."

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOoOO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOooO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1
.end method

.method public final getKey()Llyiahf/vczjk/nr1;
    .locals 1

    sget-object v0, Llyiahf/vczjk/xj0;->OooOo0o:Llyiahf/vczjk/xj0;

    return-object v0
.end method

.method public final o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p2, p1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
