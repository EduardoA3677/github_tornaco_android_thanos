.class public final synthetic Llyiahf/vczjk/p41;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/eu;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/r41;

.field public final synthetic OooO0O0:Llyiahf/vczjk/q41;

.field public final synthetic OooO0OO:Llyiahf/vczjk/wu;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/r41;Llyiahf/vczjk/q41;Llyiahf/vczjk/wu;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p41;->OooO00o:Llyiahf/vczjk/r41;

    iput-object p2, p0, Llyiahf/vczjk/p41;->OooO0O0:Llyiahf/vczjk/q41;

    iput-object p3, p0, Llyiahf/vczjk/p41;->OooO0OO:Llyiahf/vczjk/wu;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/p41;->OooO00o:Llyiahf/vczjk/r41;

    iget-object v0, v0, Llyiahf/vczjk/r41;->OooO0oO:Llyiahf/vczjk/gu;

    iget-object v1, p0, Llyiahf/vczjk/p41;->OooO0O0:Llyiahf/vczjk/q41;

    if-eqz v0, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/p41;->OooO0OO:Llyiahf/vczjk/wu;

    iget-object v1, v1, Landroidx/recyclerview/widget/o000oOoO;->OooOOO0:Landroid/view/View;

    invoke-interface {v0, v1, v2}, Llyiahf/vczjk/gu;->OooO0O0(Landroid/view/View;Llyiahf/vczjk/wu;)V

    :cond_0
    return-void
.end method
