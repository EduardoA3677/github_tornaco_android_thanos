.class public final synthetic Llyiahf/vczjk/l51;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/p51;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/util/ArrayList;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/p51;Ljava/util/ArrayList;II)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/l51;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/l51;->OooOOO:Llyiahf/vczjk/p51;

    iput-object p2, p0, Llyiahf/vczjk/l51;->OooOOOO:Ljava/util/ArrayList;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/l51;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    packed-switch v0, :pswitch_data_0

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/l51;->OooOOOO:Ljava/util/ArrayList;

    iget-object v1, p0, Llyiahf/vczjk/l51;->OooOOO:Llyiahf/vczjk/p51;

    invoke-static {v1, v0, p1, p2}, Llyiahf/vczjk/so8;->OooO0Oo(Llyiahf/vczjk/p51;Ljava/util/ArrayList;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/l51;->OooOOOO:Ljava/util/ArrayList;

    iget-object v1, p0, Llyiahf/vczjk/l51;->OooOOO:Llyiahf/vczjk/p51;

    invoke-static {v1, v0, p1, p2}, Llyiahf/vczjk/so8;->OooO0O0(Llyiahf/vczjk/p51;Ljava/util/ArrayList;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
