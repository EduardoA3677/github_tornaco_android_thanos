.class public final synthetic Llyiahf/vczjk/zy3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnLongClickListener;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/az3;

.field public final synthetic OooOOO0:Llyiahf/vczjk/bz3;

.field public final synthetic OooOOOO:Llyiahf/vczjk/wu;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/bz3;Llyiahf/vczjk/az3;Llyiahf/vczjk/wu;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zy3;->OooOOO0:Llyiahf/vczjk/bz3;

    iput-object p2, p0, Llyiahf/vczjk/zy3;->OooOOO:Llyiahf/vczjk/az3;

    iput-object p3, p0, Llyiahf/vczjk/zy3;->OooOOOO:Llyiahf/vczjk/wu;

    return-void
.end method


# virtual methods
.method public final onLongClick(Landroid/view/View;)Z
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/zy3;->OooOOO0:Llyiahf/vczjk/bz3;

    iget-object p1, p1, Llyiahf/vczjk/bz3;->OooO0o:Llyiahf/vczjk/ry3;

    if-eqz p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/zy3;->OooOOO:Llyiahf/vczjk/az3;

    iget-object v0, v0, Llyiahf/vczjk/az3;->Oooo00O:Llyiahf/vczjk/d54;

    iget-object v0, v0, Llyiahf/vczjk/d54;->OooOOO0:Landroid/widget/RelativeLayout;

    iget-object v1, p0, Llyiahf/vczjk/zy3;->OooOOOO:Llyiahf/vczjk/wu;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/ry3;->OooO0O0(Landroid/view/View;Llyiahf/vczjk/wu;)V

    :cond_0
    const/4 p1, 0x1

    return p1
.end method
