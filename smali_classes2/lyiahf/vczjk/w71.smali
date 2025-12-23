.class public final synthetic Llyiahf/vczjk/w71;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oj2;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/oj2;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/w71;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/w71;->OooOOO:Llyiahf/vczjk/oj2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/w71;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/w71;->OooOOO:Llyiahf/vczjk/oj2;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/oj2;->OooO00o(Z)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/w71;->OooOOO:Llyiahf/vczjk/oj2;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/oj2;->OooO00o(Z)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
