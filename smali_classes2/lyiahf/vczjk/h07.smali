.class public final synthetic Llyiahf/vczjk/h07;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:J


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;JI)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/h07;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/h07;->OooOOO:Ljava/lang/Object;

    iput-wide p2, p0, Llyiahf/vczjk/h07;->OooOOOO:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/h07;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/h07;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/datepicker/OooOO0O;

    iget-wide v1, p0, Llyiahf/vczjk/h07;->OooOOOO:J

    invoke-static {v1, v2}, Llyiahf/vczjk/zsa;->OoooOO0(J)Ljava/lang/String;

    move-result-object v1

    const/16 v2, 0x20

    const/16 v3, 0xa0

    invoke-virtual {v1, v2, v3}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    iget-object v2, v0, Lcom/google/android/material/datepicker/OooOO0O;->OooOOo0:Ljava/lang/String;

    invoke-static {v2, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    iget-object v2, v0, Lcom/google/android/material/datepicker/OooOO0O;->OooOOO0:Lcom/google/android/material/textfield/TextInputLayout;

    invoke-virtual {v2, v1}, Lcom/google/android/material/textfield/TextInputLayout;->setError(Ljava/lang/CharSequence;)V

    invoke-virtual {v0}, Lcom/google/android/material/datepicker/OooOO0O;->OooO00o()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/h07;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/k07;

    iget-wide v1, p0, Llyiahf/vczjk/h07;->OooOOOO:J

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/k07;->OooOoO0(Llyiahf/vczjk/k07;J)V

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/h07;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/k07;

    iget-wide v1, p0, Llyiahf/vczjk/h07;->OooOOOO:J

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/k07;->OooOo0(Llyiahf/vczjk/k07;J)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
