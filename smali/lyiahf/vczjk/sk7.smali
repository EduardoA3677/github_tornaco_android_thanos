.class public final Llyiahf/vczjk/sk7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Landroid/util/SparseArray;

.field public OooO0O0:I

.field public OooO0OO:Ljava/util/Set;


# virtual methods
.method public final OooO00o(I)Llyiahf/vczjk/rk7;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/sk7;->OooO00o:Landroid/util/SparseArray;

    invoke-virtual {v0, p1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rk7;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/rk7;

    invoke-direct {v1}, Llyiahf/vczjk/rk7;-><init>()V

    invoke-virtual {v0, p1, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    :cond_0
    return-object v1
.end method
