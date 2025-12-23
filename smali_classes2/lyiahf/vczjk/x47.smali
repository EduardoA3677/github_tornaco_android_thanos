.class public final synthetic Llyiahf/vczjk/x47;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a57;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a57;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/x47;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/x47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/x47;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "SenorOff sensorOffDisableRunnable run."

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    const/4 v0, 0x0

    const-string v1, "sensorOffDisableRunnable"

    iget-object v2, p0, Llyiahf/vczjk/x47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-virtual {v2, v1, v0}, Llyiahf/vczjk/a57;->Oooo00o(Ljava/lang/String;Z)V

    return-void

    :pswitch_0
    const/4 v0, 0x0

    const-string v1, "setSensorOffEnabled"

    iget-object v2, p0, Llyiahf/vczjk/x47;->OooOOO:Llyiahf/vczjk/a57;

    invoke-virtual {v2, v1, v0}, Llyiahf/vczjk/a57;->Oooo00o(Ljava/lang/String;Z)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
