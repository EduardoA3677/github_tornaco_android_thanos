.class public final Llyiahf/vczjk/x56;
.super Llyiahf/vczjk/wt9;
.source "SourceFile"


# static fields
.field public static final OooOOOo:Llyiahf/vczjk/x56;

.field public static final OooOOo0:Llyiahf/vczjk/x56;


# instance fields
.field public final synthetic OooOOOO:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/x56;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/x56;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/x56;->OooOOOo:Llyiahf/vczjk/x56;

    new-instance v0, Llyiahf/vczjk/x56;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/x56;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/x56;->OooOOo0:Llyiahf/vczjk/x56;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Llyiahf/vczjk/x56;->OooOOOO:I

    packed-switch p1, :pswitch_data_0

    const-class p1, Ljava/math/BigDecimal;

    const/4 v0, 0x0

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/wt9;-><init>(ILjava/lang/Class;)V

    return-void

    :pswitch_0
    const-class p1, Ljava/lang/Object;

    const/4 v0, 0x0

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/wt9;-><init>(ILjava/lang/Class;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public synthetic constructor <init>(ILjava/lang/Class;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/x56;->OooOOOO:I

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/wt9;-><init>(ILjava/lang/Class;)V

    return-void
.end method


# virtual methods
.method public OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/x56;->OooOOOO:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/wt9;->OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z

    move-result p1

    return p1

    :pswitch_0
    const/4 p1, 0x0

    return p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/x56;->OooOOOO:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1, p2, p3}, Llyiahf/vczjk/wt9;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :pswitch_0
    sget-object v0, Llyiahf/vczjk/t94;->OooOo00:Llyiahf/vczjk/t94;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/u94;->OooOooo(Llyiahf/vczjk/t94;)Z

    move-result v0

    if-eqz v0, :cond_1

    check-cast p1, Ljava/math/BigDecimal;

    invoke-virtual {p1}, Ljava/math/BigDecimal;->scale()I

    move-result v0

    const/16 v1, -0x270f

    const/16 v2, 0x270f

    if-lt v0, v1, :cond_0

    if-gt v0, v2, :cond_0

    invoke-virtual {p1}, Ljava/math/BigDecimal;->toPlainString()Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Ljava/math/BigDecimal;->scale()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {p1, p2, v0}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Attempt to write plain `java.math.BigDecimal` (see JsonGenerator.Feature.WRITE_BIGDECIMAL_AS_PLAIN) with illegal scale (%d): needs to be between [-%d, %d]"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast p3, Llyiahf/vczjk/w32;

    iget-object p2, p3, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    new-instance p3, Llyiahf/vczjk/na4;

    const/4 v0, 0x0

    invoke-direct {p3, p2, p1, v0}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p3

    :cond_1
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    :goto_0
    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000ooO(Ljava/lang/String;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOOO(Ljava/lang/Object;)Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/x56;->OooOOOO:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_0
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1}, Ljava/lang/IllegalStateException;-><init>()V

    throw p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
