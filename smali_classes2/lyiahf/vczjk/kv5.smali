.class public final synthetic Llyiahf/vczjk/kv5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/x39;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/x39;II)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/kv5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/kv5;->OooOOO:Llyiahf/vczjk/x39;

    iput p2, p0, Llyiahf/vczjk/kv5;->OooOOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/kv5;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    packed-switch v0, :pswitch_data_0

    iget p2, p0, Llyiahf/vczjk/kv5;->OooOOOO:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/kv5;->OooOOO:Llyiahf/vczjk/x39;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/tg0;->OooOO0(Llyiahf/vczjk/x39;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    iget p2, p0, Llyiahf/vczjk/kv5;->OooOOOO:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/kv5;->OooOOO:Llyiahf/vczjk/x39;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/tg0;->OooOOO0(Llyiahf/vczjk/x39;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    iget p2, p0, Llyiahf/vczjk/kv5;->OooOOOO:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/kv5;->OooOOO:Llyiahf/vczjk/x39;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/tg0;->OooO0oO(Llyiahf/vczjk/x39;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
