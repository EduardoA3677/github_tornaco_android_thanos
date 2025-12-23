.class public final synthetic Llyiahf/vczjk/io9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ro9;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ro9;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/io9;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/io9;->OooOOO:Llyiahf/vczjk/ro9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/io9;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/l30;

    iget-object v1, p0, Llyiahf/vczjk/io9;->OooOOO:Llyiahf/vczjk/ro9;

    iget-object v1, v1, Llyiahf/vczjk/ro9;->OooO00o:Lnow/fortuitous/thanos/ThanosApp;

    invoke-direct {v0, v1}, Llyiahf/vczjk/l30;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/u18;

    iget-object v1, p0, Llyiahf/vczjk/io9;->OooOOO:Llyiahf/vczjk/ro9;

    iget-object v1, v1, Llyiahf/vczjk/ro9;->OooO00o:Lnow/fortuitous/thanos/ThanosApp;

    invoke-direct {v0, v1}, Llyiahf/vczjk/u18;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/io9;->OooOOO:Llyiahf/vczjk/ro9;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/util/HandlerUtils;->newHandlerOfNewThread(Ljava/lang/String;)Landroid/os/Handler;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
