.class public final synthetic Llyiahf/vczjk/n85;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u85;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/v85;

.field public final synthetic OooO0OO:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/v85;Ljava/lang/String;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/n85;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/n85;->OooO0O0:Llyiahf/vczjk/v85;

    iput-object p2, p0, Llyiahf/vczjk/n85;->OooO0OO:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/n85;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/n85;->OooO0O0:Llyiahf/vczjk/v85;

    iget-object v1, p0, Llyiahf/vczjk/n85;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/v85;->OooOo0(Ljava/lang/String;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/n85;->OooO0O0:Llyiahf/vczjk/v85;

    iget-object v1, p0, Llyiahf/vczjk/n85;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/v85;->OooOOo(Ljava/lang/String;)V

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/n85;->OooO0O0:Llyiahf/vczjk/v85;

    iget-object v1, p0, Llyiahf/vczjk/n85;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/v85;->OooOOoo(Ljava/lang/String;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
