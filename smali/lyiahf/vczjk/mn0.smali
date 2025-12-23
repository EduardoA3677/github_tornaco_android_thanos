.class public final Llyiahf/vczjk/mn0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/s48;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/s48;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/mn0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/mn0;->OooOOO:Llyiahf/vczjk/s48;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/mn0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/dk6;

    invoke-direct {v0, p1}, Llyiahf/vczjk/dk6;-><init>(Llyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/mn0;->OooOOO:Llyiahf/vczjk/s48;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/o00O0000;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/ln0;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ln0;-><init>(Llyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/mn0;->OooOOO:Llyiahf/vczjk/s48;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/o00O0000;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_1
    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
