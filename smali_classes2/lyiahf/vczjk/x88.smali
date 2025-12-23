.class public Llyiahf/vczjk/x88;
.super Llyiahf/vczjk/o000O000;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/zr1;


# instance fields
.field public final OooOOOo:Llyiahf/vczjk/yo1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V
    .locals 1

    const/4 v0, 0x1

    invoke-direct {p0, p2, v0}, Llyiahf/vczjk/o000O000;-><init>(Llyiahf/vczjk/or1;Z)V

    iput-object p1, p0, Llyiahf/vczjk/x88;->OooOOOo:Llyiahf/vczjk/yo1;

    return-void
.end method


# virtual methods
.method public OooOO0(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x88;->OooOOOo:Llyiahf/vczjk/yo1;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v0

    invoke-static {p1}, Llyiahf/vczjk/c6a;->o00o0O(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1, v0}, Llyiahf/vczjk/dn8;->o00oO0O(Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    return-void
.end method

.method public OooOOO(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x88;->OooOOOo:Llyiahf/vczjk/yo1;

    invoke-static {p1}, Llyiahf/vczjk/c6a;->o00o0O(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-interface {v0, p1}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

.method public final Oooo0o()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public OoooooO()V
    .locals 0

    return-void
.end method

.method public final getCallerFrame()Llyiahf/vczjk/zr1;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/x88;->OooOOOo:Llyiahf/vczjk/yo1;

    instance-of v1, v0, Llyiahf/vczjk/zr1;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/zr1;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method
