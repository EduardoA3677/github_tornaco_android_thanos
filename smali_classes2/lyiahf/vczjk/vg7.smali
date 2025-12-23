.class public final Llyiahf/vczjk/vg7;
.super Llyiahf/vczjk/l21;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOo:Llyiahf/vczjk/nk4;

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/nk4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/vg7;->OooOOo0:I

    iput-object p1, p0, Llyiahf/vczjk/vg7;->OooOOo:Llyiahf/vczjk/nk4;

    invoke-direct {p0}, Llyiahf/vczjk/l21;-><init>()V

    return-void
.end method


# virtual methods
.method public final o0000O00([Ljava/lang/String;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/vg7;->OooOOo0:I

    packed-switch v0, :pswitch_data_0

    if-eqz p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/vg7;->OooOOo:Llyiahf/vczjk/nk4;

    check-cast v0, Llyiahf/vczjk/tqa;

    iget-object v0, v0, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yg7;

    iput-object p1, v0, Llyiahf/vczjk/yg7;->OooO0oo:[Ljava/lang/String;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Argument for @NotNull parameter \'result\' of kotlin/reflect/jvm/internal/impl/load/kotlin/header/ReadKotlinClassHeaderAnnotationVisitor$KotlinSerializedIrArgumentVisitor$1.visitEnd must not be null"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    if-eqz p1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/vg7;->OooOOo:Llyiahf/vczjk/nk4;

    check-cast v0, Llyiahf/vczjk/wg7;

    iget-object v0, v0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yg7;

    iput-object p1, v0, Llyiahf/vczjk/yg7;->OooO0o0:[Ljava/lang/String;

    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Argument for @NotNull parameter \'result\' of kotlin/reflect/jvm/internal/impl/load/kotlin/header/ReadKotlinClassHeaderAnnotationVisitor$KotlinMetadataArgumentVisitor$2.visitEnd must not be null"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_1
    if-eqz p1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/vg7;->OooOOo:Llyiahf/vczjk/nk4;

    check-cast v0, Llyiahf/vczjk/wg7;

    iget-object v0, v0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yg7;

    iput-object p1, v0, Llyiahf/vczjk/yg7;->OooO0Oo:[Ljava/lang/String;

    return-void

    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Argument for @NotNull parameter \'result\' of kotlin/reflect/jvm/internal/impl/load/kotlin/header/ReadKotlinClassHeaderAnnotationVisitor$KotlinMetadataArgumentVisitor$1.visitEnd must not be null"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
