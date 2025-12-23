.class public final Llyiahf/vczjk/ny9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/p29;


# instance fields
.field public OooOOO:Llyiahf/vczjk/rm4;

.field public final OooOOO0:Llyiahf/vczjk/uy9;

.field public OooOOOO:Llyiahf/vczjk/rm4;

.field public final synthetic OooOOOo:Llyiahf/vczjk/oy9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oy9;Llyiahf/vczjk/uy9;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ny9;->OooOOOo:Llyiahf/vczjk/oy9;

    iput-object p2, p0, Llyiahf/vczjk/ny9;->OooOOO0:Llyiahf/vczjk/uy9;

    check-cast p3, Llyiahf/vczjk/rm4;

    iput-object p3, p0, Llyiahf/vczjk/ny9;->OooOOO:Llyiahf/vczjk/rm4;

    check-cast p4, Llyiahf/vczjk/rm4;

    iput-object p4, p0, Llyiahf/vczjk/ny9;->OooOOOO:Llyiahf/vczjk/rm4;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/sy9;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ny9;->OooOOOO:Llyiahf/vczjk/rm4;

    invoke-interface {p1}, Llyiahf/vczjk/sy9;->OooO0OO()Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ny9;->OooOOOo:Llyiahf/vczjk/oy9;

    iget-object v1, v1, Llyiahf/vczjk/oy9;->OooO0OO:Llyiahf/vczjk/bz9;

    invoke-virtual {v1}, Llyiahf/vczjk/bz9;->OooO()Z

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/ny9;->OooOOO0:Llyiahf/vczjk/uy9;

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/ny9;->OooOOOO:Llyiahf/vczjk/rm4;

    invoke-interface {p1}, Llyiahf/vczjk/sy9;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    invoke-interface {v1, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    iget-object v3, p0, Llyiahf/vczjk/ny9;->OooOOO:Llyiahf/vczjk/rm4;

    invoke-interface {v3, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p13;

    invoke-virtual {v2, v1, v0, p1}, Llyiahf/vczjk/uy9;->OooO0oo(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/p13;)V

    return-void

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/ny9;->OooOOO:Llyiahf/vczjk/rm4;

    invoke-interface {v1, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p13;

    invoke-virtual {v2, v0, p1}, Llyiahf/vczjk/uy9;->OooO(Ljava/lang/Object;Llyiahf/vczjk/p13;)V

    return-void
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ny9;->OooOOOo:Llyiahf/vczjk/oy9;

    iget-object v0, v0, Llyiahf/vczjk/oy9;->OooO0OO:Llyiahf/vczjk/bz9;

    invoke-virtual {v0}, Llyiahf/vczjk/bz9;->OooO0o()Llyiahf/vczjk/sy9;

    move-result-object v0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ny9;->OooO00o(Llyiahf/vczjk/sy9;)V

    iget-object v0, p0, Llyiahf/vczjk/ny9;->OooOOO0:Llyiahf/vczjk/uy9;

    iget-object v0, v0, Llyiahf/vczjk/uy9;->OooOo0O:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method
