.class public final Llyiahf/vczjk/af;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ux6;
.implements Llyiahf/vczjk/xr1;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/tl9;

.field public final OooOOO0:Landroid/view/View;

.field public final OooOOOO:Llyiahf/vczjk/xr1;

.field public final OooOOOo:Ljava/util/concurrent/atomic/AtomicReference;


# direct methods
.method public constructor <init>(Landroid/view/View;Llyiahf/vczjk/tl9;Llyiahf/vczjk/xr1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/af;->OooOOO0:Landroid/view/View;

    iput-object p2, p0, Llyiahf/vczjk/af;->OooOOO:Llyiahf/vczjk/tl9;

    iput-object p3, p0, Llyiahf/vczjk/af;->OooOOOO:Llyiahf/vczjk/xr1;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/af;->OooOOOo:Ljava/util/concurrent/atomic/AtomicReference;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nx4;Llyiahf/vczjk/zo1;)V
    .locals 5

    instance-of v0, p2, Llyiahf/vczjk/ve;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/ve;

    iget v1, v0, Llyiahf/vczjk/ve;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ve;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ve;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/ve;-><init>(Llyiahf/vczjk/af;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/ve;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ve;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-eq v2, v3, :cond_1

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/af;->OooOOOo:Ljava/util/concurrent/atomic/AtomicReference;

    new-instance v2, Llyiahf/vczjk/xe;

    invoke-direct {v2, p1, p0}, Llyiahf/vczjk/xe;-><init>(Llyiahf/vczjk/nx4;Llyiahf/vczjk/af;)V

    new-instance p1, Llyiahf/vczjk/ze;

    const/4 v4, 0x0

    invoke-direct {p1, p0, v4}, Llyiahf/vczjk/ze;-><init>(Llyiahf/vczjk/af;Llyiahf/vczjk/yo1;)V

    iput v3, v0, Llyiahf/vczjk/ve;->label:I

    new-instance v3, Llyiahf/vczjk/fh8;

    invoke-direct {v3, v2, p2, p1, v4}, Llyiahf/vczjk/fh8;-><init>(Llyiahf/vczjk/oe3;Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-void

    :cond_3
    :goto_1
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
.end method

.method public final OoooOO0()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/af;->OooOOOO:Llyiahf/vczjk/xr1;

    invoke-interface {v0}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object v0

    return-object v0
.end method
