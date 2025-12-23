.class public final Llyiahf/vczjk/vv1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le7;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/wv1;

.field public final OooO0O0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wv1;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vv1;->OooO00o:Llyiahf/vczjk/wv1;

    iput p2, p0, Llyiahf/vczjk/vv1;->OooO0O0:I

    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/vv1;->OooO00o:Llyiahf/vczjk/wv1;

    iget v1, p0, Llyiahf/vczjk/vv1;->OooO0O0:I

    if-eqz v1, :cond_4

    const/4 v2, 0x1

    if-eq v1, v2, :cond_3

    const/4 v2, 0x2

    if-eq v1, v2, :cond_2

    const/4 v2, 0x3

    if-eq v1, v2, :cond_1

    const/4 v2, 0x4

    if-ne v1, v2, :cond_0

    new-instance v1, Llyiahf/vczjk/f28;

    iget-object v0, v0, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v0, v0, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v1, v0}, Llyiahf/vczjk/f28;-><init>(Landroid/content/Context;)V

    return-object v1

    :cond_0
    new-instance v0, Ljava/lang/AssertionError;

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(I)V

    throw v0

    :cond_1
    new-instance v1, Llyiahf/vczjk/u18;

    iget-object v0, v0, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v0, v0, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v1, v0}, Llyiahf/vczjk/u18;-><init>(Landroid/content/Context;)V

    return-object v1

    :cond_2
    new-instance v1, Llyiahf/vczjk/e28;

    iget-object v0, v0, Llyiahf/vczjk/wv1;->OooO0o0:Llyiahf/vczjk/le7;

    invoke-interface {v0}, Llyiahf/vczjk/le7;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/u18;

    invoke-direct {v1, v0}, Llyiahf/vczjk/e28;-><init>(Llyiahf/vczjk/u18;)V

    return-object v1

    :cond_3
    new-instance v1, Llyiahf/vczjk/l30;

    iget-object v0, v0, Llyiahf/vczjk/wv1;->OooO00o:Llyiahf/vczjk/ax;

    iget-object v0, v0, Llyiahf/vczjk/ax;->OooO00o:Landroid/content/Context;

    invoke-direct {v1, v0}, Llyiahf/vczjk/l30;-><init>(Landroid/content/Context;)V

    return-object v1

    :cond_4
    new-instance v1, Llyiahf/vczjk/o30;

    iget-object v0, v0, Llyiahf/vczjk/wv1;->OooO0OO:Llyiahf/vczjk/le7;

    invoke-interface {v0}, Llyiahf/vczjk/le7;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/l30;

    invoke-direct {v1, v0}, Llyiahf/vczjk/o30;-><init>(Llyiahf/vczjk/l30;)V

    return-object v1
.end method
