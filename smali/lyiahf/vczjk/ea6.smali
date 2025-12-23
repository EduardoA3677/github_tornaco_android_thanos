.class public final Llyiahf/vczjk/ea6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/window/OnBackAnimationCallback;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/z96;

.field public final synthetic OooO0O0:Llyiahf/vczjk/aa6;

.field public final synthetic OooO0OO:Llyiahf/vczjk/ba6;

.field public final synthetic OooO0Oo:Llyiahf/vczjk/ca6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/z96;Llyiahf/vczjk/aa6;Llyiahf/vczjk/ba6;Llyiahf/vczjk/ca6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ea6;->OooO00o:Llyiahf/vczjk/z96;

    iput-object p2, p0, Llyiahf/vczjk/ea6;->OooO0O0:Llyiahf/vczjk/aa6;

    iput-object p3, p0, Llyiahf/vczjk/ea6;->OooO0OO:Llyiahf/vczjk/ba6;

    iput-object p4, p0, Llyiahf/vczjk/ea6;->OooO0Oo:Llyiahf/vczjk/ca6;

    return-void
.end method


# virtual methods
.method public final onBackCancelled()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ea6;->OooO0Oo:Llyiahf/vczjk/ca6;

    invoke-virtual {v0}, Llyiahf/vczjk/ca6;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public final onBackInvoked()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ea6;->OooO0OO:Llyiahf/vczjk/ba6;

    invoke-virtual {v0}, Llyiahf/vczjk/ba6;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public final onBackProgressed(Landroid/window/BackEvent;)V
    .locals 2

    const-string v0, "backEvent"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ea6;->OooO0O0:Llyiahf/vczjk/aa6;

    new-instance v1, Llyiahf/vczjk/n40;

    invoke-direct {v1, p1}, Llyiahf/vczjk/n40;-><init>(Landroid/window/BackEvent;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/aa6;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final onBackStarted(Landroid/window/BackEvent;)V
    .locals 2

    const-string v0, "backEvent"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ea6;->OooO00o:Llyiahf/vczjk/z96;

    new-instance v1, Llyiahf/vczjk/n40;

    invoke-direct {v1, p1}, Llyiahf/vczjk/n40;-><init>(Landroid/window/BackEvent;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/z96;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method
