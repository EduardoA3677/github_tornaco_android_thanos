.class public final Llyiahf/vczjk/tga;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/tga;

.field public static final OooOOOO:Llyiahf/vczjk/tga;

.field public static final OooOOOo:Llyiahf/vczjk/tga;

.field public static final OooOOo0:Llyiahf/vczjk/tga;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/tga;

    const/4 v1, 0x1

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/tga;-><init>(II)V

    sput-object v0, Llyiahf/vczjk/tga;->OooOOO:Llyiahf/vczjk/tga;

    new-instance v0, Llyiahf/vczjk/tga;

    const/4 v1, 0x1

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/tga;-><init>(II)V

    sput-object v0, Llyiahf/vczjk/tga;->OooOOOO:Llyiahf/vczjk/tga;

    new-instance v0, Llyiahf/vczjk/tga;

    const/4 v1, 0x1

    const/4 v2, 0x2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/tga;-><init>(II)V

    sput-object v0, Llyiahf/vczjk/tga;->OooOOOo:Llyiahf/vczjk/tga;

    new-instance v0, Llyiahf/vczjk/tga;

    const/4 v1, 0x1

    const/4 v2, 0x3

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/tga;-><init>(II)V

    sput-object v0, Llyiahf/vczjk/tga;->OooOOo0:Llyiahf/vczjk/tga;

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/tga;->OooOOO0:I

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tga;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/pj1;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_0
    const/4 p1, 0x0

    return-object p1

    :pswitch_1
    const/4 p1, 0x0

    return-object p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/rga;

    invoke-virtual {p1}, Llyiahf/vczjk/rga;->OooO00o()Ljava/util/ArrayList;

    move-result-object p1

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
