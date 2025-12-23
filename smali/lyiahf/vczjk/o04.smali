.class public final Llyiahf/vczjk/o04;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Landroid/view/View;

.field public final OooO0O0:Ljava/lang/Object;

.field public final OooO0OO:Llyiahf/vczjk/wg7;


# direct methods
.method public constructor <init>(Landroid/view/View;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o04;->OooO00o:Landroid/view/View;

    sget-object v0, Llyiahf/vczjk/ww4;->OooOOO:Llyiahf/vczjk/ww4;

    new-instance v1, Llyiahf/vczjk/m04;

    invoke-direct {v1, p0}, Llyiahf/vczjk/m04;-><init>(Llyiahf/vczjk/o04;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/o04;->OooO0O0:Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/wg7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/wg7;-><init>(Landroid/view/View;)V

    iput-object v0, p0, Llyiahf/vczjk/o04;->OooO0OO:Llyiahf/vczjk/wg7;

    return-void
.end method
