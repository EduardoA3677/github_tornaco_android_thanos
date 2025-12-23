.class public final Llyiahf/vczjk/te9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/ue9;

.field public final synthetic OooOOOo:Llyiahf/vczjk/ve9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ve9;IILlyiahf/vczjk/ue9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/te9;->OooOOOo:Llyiahf/vczjk/ve9;

    iput p2, p0, Llyiahf/vczjk/te9;->OooOOO0:I

    iput p3, p0, Llyiahf/vczjk/te9;->OooOOO:I

    iput-object p4, p0, Llyiahf/vczjk/te9;->OooOOOO:Llyiahf/vczjk/ue9;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/te9;->OooOOOo:Llyiahf/vczjk/ve9;

    iget-object v1, v0, Llyiahf/vczjk/ve9;->OooOo0o:Llyiahf/vczjk/qx7;

    if-eqz v1, :cond_0

    iget-object v2, v0, Llyiahf/vczjk/ve9;->OooOOOO:Ljava/util/ArrayList;

    iget v3, p0, Llyiahf/vczjk/te9;->OooOOO0:I

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    iget v2, p0, Llyiahf/vczjk/te9;->OooOOO:I

    iget-object v4, p0, Llyiahf/vczjk/te9;->OooOOOO:Llyiahf/vczjk/ue9;

    invoke-virtual {v0, v3, v2, v4}, Llyiahf/vczjk/ve9;->OooO00o(IILlyiahf/vczjk/ue9;)V

    iget-object v0, v1, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ra;

    iget-object v1, v1, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/dv1;

    invoke-virtual {v1, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    invoke-virtual {v1, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    :cond_0
    return-void
.end method
