.class public final Llyiahf/vczjk/gg5;
.super Llyiahf/vczjk/hg5;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/gg5;

.field public static final OooO0o0:Llyiahf/vczjk/gg5;


# instance fields
.field public final synthetic OooO0OO:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/gg5;

    const-string v1, "must be a member function"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/gg5;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/gg5;->OooO0Oo:Llyiahf/vczjk/gg5;

    new-instance v0, Llyiahf/vczjk/gg5;

    const-string v1, "must be a member or an extension function"

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/gg5;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/gg5;->OooO0o0:Llyiahf/vczjk/gg5;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/gg5;->OooO0OO:I

    const/4 p2, 0x0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/hg5;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/o64;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/gg5;->OooO0OO:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p1, Llyiahf/vczjk/tf3;->OooOoO0:Llyiahf/vczjk/mp4;

    if-nez v0, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/tf3;->OooOo:Llyiahf/vczjk/mp4;

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    :goto_1
    return p1

    :pswitch_0
    iget-object p1, p1, Llyiahf/vczjk/tf3;->OooOoO0:Llyiahf/vczjk/mp4;

    if-eqz p1, :cond_2

    const/4 p1, 0x1

    goto :goto_2

    :cond_2
    const/4 p1, 0x0

    :goto_2
    return p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
