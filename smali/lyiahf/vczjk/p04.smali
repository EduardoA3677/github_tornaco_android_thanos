.class public final Llyiahf/vczjk/p04;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/l04;


# instance fields
.field public final OooO00o:Landroid/view/View;

.field public final OooO0O0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/view/View;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p04;->OooO00o:Landroid/view/View;

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO:Llyiahf/vczjk/ww4;

    new-instance v0, Llyiahf/vczjk/n04;

    invoke-direct {v0, p0}, Llyiahf/vczjk/n04;-><init>(Llyiahf/vczjk/p04;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/p04;->OooO0O0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()Landroid/view/inputmethod/InputMethodManager;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/p04;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/inputmethod/InputMethodManager;

    return-object v0
.end method
