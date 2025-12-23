.class public final synthetic Llyiahf/vczjk/sg7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/tg7;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/tg7;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/sg7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/sg7;->OooOOO:Llyiahf/vczjk/tg7;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/sg7;->OooOOO0:I

    check-cast p1, Ljava/util/HashMap;

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/sg7;->OooOOO:Llyiahf/vczjk/tg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/tg7;->OooO0O0(Ljava/util/HashMap;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/sg7;->OooOOO:Llyiahf/vczjk/tg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/tg7;->OooOOo0(Ljava/util/HashMap;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
