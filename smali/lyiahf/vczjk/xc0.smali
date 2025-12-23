.class public final Llyiahf/vczjk/xc0;
.super Llyiahf/vczjk/fc3;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOO:I

.field public OooOOOO:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a96;Llyiahf/vczjk/nj0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/xc0;->OooOOO:I

    iput-object p1, p0, Llyiahf/vczjk/xc0;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0, p2}, Llyiahf/vczjk/fc3;-><init>(Llyiahf/vczjk/rx8;)V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/rx8;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/xc0;->OooOOO:I

    invoke-direct {p0, p1}, Llyiahf/vczjk/fc3;-><init>(Llyiahf/vczjk/rx8;)V

    return-void
.end method


# virtual methods
.method public final o0O0O00(Llyiahf/vczjk/yi0;J)J
    .locals 1

    iget v0, p0, Llyiahf/vczjk/xc0;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    :try_start_0
    invoke-super {p0, p1, p2, p3}, Llyiahf/vczjk/fc3;->o0O0O00(Llyiahf/vczjk/yi0;J)J

    move-result-wide p1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-wide p1

    :catch_0
    move-exception p1

    iget-object p2, p0, Llyiahf/vczjk/xc0;->OooOOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/a96;

    iput-object p1, p2, Llyiahf/vczjk/a96;->OooOOOo:Ljava/io/IOException;

    throw p1

    :pswitch_0
    :try_start_1
    invoke-super {p0, p1, p2, p3}, Llyiahf/vczjk/fc3;->o0O0O00(Llyiahf/vczjk/yi0;J)J

    move-result-wide p1
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    return-wide p1

    :catch_1
    move-exception p1

    iput-object p1, p0, Llyiahf/vczjk/xc0;->OooOOOO:Ljava/lang/Object;

    throw p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
