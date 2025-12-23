.class public final synthetic Llyiahf/vczjk/oOO00000;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Landroid/content/Intent;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Landroid/content/Intent;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/oOO00000;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/oOO00000;->OooOOO:Landroid/content/Intent;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/oOO00000;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;

    iget-object v1, p0, Llyiahf/vczjk/oOO00000;->OooOOO:Landroid/content/Intent;

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;-><init>(Landroid/content/Intent;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/hr2;->OooO0O0(Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;)V

    return-void

    :pswitch_0
    new-instance v0, Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;

    iget-object v1, p0, Llyiahf/vczjk/oOO00000;->OooOOO:Landroid/content/Intent;

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;-><init>(Landroid/content/Intent;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/hr2;->OooO0O0(Lgithub/tornaco/android/thanos/core/app/event/ThanosEvent;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
