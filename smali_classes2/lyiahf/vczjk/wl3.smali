.class public final synthetic Llyiahf/vczjk/wl3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sc2;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Runnable;

.field public final synthetic OooOOO0:Llyiahf/vczjk/xl3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xl3;Ljava/lang/Runnable;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wl3;->OooOOO0:Llyiahf/vczjk/xl3;

    iput-object p2, p0, Llyiahf/vczjk/wl3;->OooOOO:Ljava/lang/Runnable;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/wl3;->OooOOO0:Llyiahf/vczjk/xl3;

    iget-object v0, v0, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    iget-object v1, p0, Llyiahf/vczjk/wl3;->OooOOO:Ljava/lang/Runnable;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    return-void
.end method
