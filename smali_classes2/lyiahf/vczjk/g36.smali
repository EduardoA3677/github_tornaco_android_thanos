.class public final synthetic Llyiahf/vczjk/g36;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/i36;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/i36;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/g36;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/g36;->OooOOO:Llyiahf/vczjk/i36;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/g36;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/g36;->OooOOO:Llyiahf/vczjk/i36;

    invoke-virtual {v0}, Llyiahf/vczjk/i36;->OooOoo()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/g36;->OooOOO:Llyiahf/vczjk/i36;

    invoke-virtual {v0}, Llyiahf/vczjk/i36;->OooOo()Lgithub/tornaco/android/thanos/db/n/NRDb;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/db/n/NRDb;->nrDao()Lgithub/tornaco/android/thanos/db/n/NRDao;

    move-result-object v0

    invoke-interface {v0}, Lgithub/tornaco/android/thanos/db/n/NRDao;->deleteAll()V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
