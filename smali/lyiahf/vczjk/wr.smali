.class public final Llyiahf/vczjk/wr;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/widget/PopupWindow$OnDismissListener;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/xr;

.field public final synthetic OooOOO0:Llyiahf/vczjk/oOo000o0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr;Llyiahf/vczjk/oOo000o0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wr;->OooOOO:Llyiahf/vczjk/xr;

    iput-object p2, p0, Llyiahf/vczjk/wr;->OooOOO0:Llyiahf/vczjk/oOo000o0;

    return-void
.end method


# virtual methods
.method public final onDismiss()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/wr;->OooOOO:Llyiahf/vczjk/xr;

    iget-object v0, v0, Llyiahf/vczjk/xr;->OoooO0O:Landroidx/appcompat/widget/AppCompatSpinner;

    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/wr;->OooOOO0:Llyiahf/vczjk/oOo000o0;

    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->removeGlobalOnLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    :cond_0
    return-void
.end method
