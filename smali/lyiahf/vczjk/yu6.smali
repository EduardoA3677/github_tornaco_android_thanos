.class public final Llyiahf/vczjk/yu6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bz5;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/zu6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zu6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yu6;->OooOOO0:Llyiahf/vczjk/zu6;

    return-void
.end method


# virtual methods
.method public final OooOoOO(JJLlyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 2

    invoke-static {p3, p4}, Llyiahf/vczjk/fea;->OooO0OO(J)F

    move-result v0

    const/4 v1, 0x0

    cmpl-float v0, v0, v1

    if-lez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/yu6;->OooOOO0:Llyiahf/vczjk/zu6;

    iget-object v0, v0, Llyiahf/vczjk/zu6;->OooO00o:Llyiahf/vczjk/kx9;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/kx9;->OooO0OO(F)V

    :cond_0
    invoke-super/range {p0 .. p5}, Llyiahf/vczjk/bz5;->OooOoOO(JJLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final Ooooooo(IJJ)J
    .locals 4

    iget-object p1, p0, Llyiahf/vczjk/yu6;->OooOOO0:Llyiahf/vczjk/zu6;

    iget-object p4, p1, Llyiahf/vczjk/zu6;->OooO0O0:Llyiahf/vczjk/le3;

    invoke-interface {p4}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Ljava/lang/Boolean;

    invoke-virtual {p4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p4

    const-wide/16 v0, 0x0

    if-nez p4, :cond_0

    return-wide v0

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/zu6;->OooO00o:Llyiahf/vczjk/kx9;

    iget-object p4, p1, Llyiahf/vczjk/kx9;->OooO0O0:Llyiahf/vczjk/lr5;

    check-cast p4, Llyiahf/vczjk/zv8;

    invoke-virtual {p4}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result p4

    const-wide v2, 0xffffffffL

    and-long/2addr p2, v2

    long-to-int p2, p2

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    add-float/2addr p2, p4

    invoke-virtual {p1, p2}, Llyiahf/vczjk/kx9;->OooO0OO(F)V

    return-wide v0
.end method
