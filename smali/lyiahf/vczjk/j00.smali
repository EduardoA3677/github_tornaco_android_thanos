.class public final Llyiahf/vczjk/j00;
.super Llyiahf/vczjk/un6;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/no7;


# static fields
.field public static final Oooo00O:Llyiahf/vczjk/ow;


# instance fields
.field public OooOOo:Llyiahf/vczjk/to1;

.field public final OooOOoo:Llyiahf/vczjk/s29;

.field public OooOo:Llyiahf/vczjk/un6;

.field public final OooOo0:Llyiahf/vczjk/lr5;

.field public final OooOo00:Llyiahf/vczjk/qs5;

.field public final OooOo0O:Llyiahf/vczjk/qs5;

.field public OooOo0o:Llyiahf/vczjk/c00;

.field public OooOoO:Llyiahf/vczjk/fi2;

.field public OooOoO0:Llyiahf/vczjk/oe3;

.field public OooOoOO:Llyiahf/vczjk/en1;

.field public OooOoo:Z

.field public OooOoo0:I

.field public final OooOooO:Llyiahf/vczjk/qs5;

.field public final OooOooo:Llyiahf/vczjk/qs5;

.field public final Oooo000:Llyiahf/vczjk/qs5;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ow;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/ow;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/j00;->Oooo00O:Llyiahf/vczjk/ow;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/kv3;Llyiahf/vczjk/fv3;)V
    .locals 3

    invoke-direct {p0}, Llyiahf/vczjk/un6;-><init>()V

    new-instance v0, Llyiahf/vczjk/tq8;

    const-wide/16 v1, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/tq8;-><init>(J)V

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/j00;->OooOOoo:Llyiahf/vczjk/s29;

    const/4 v0, 0x0

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/j00;->OooOo00:Llyiahf/vczjk/qs5;

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-static {v1}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/j00;->OooOo0:Llyiahf/vczjk/lr5;

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/j00;->OooOo0O:Llyiahf/vczjk/qs5;

    sget-object v0, Llyiahf/vczjk/yz;->OooO00o:Llyiahf/vczjk/yz;

    iput-object v0, p0, Llyiahf/vczjk/j00;->OooOo0o:Llyiahf/vczjk/c00;

    sget-object v1, Llyiahf/vczjk/j00;->Oooo00O:Llyiahf/vczjk/ow;

    iput-object v1, p0, Llyiahf/vczjk/j00;->OooOoO0:Llyiahf/vczjk/oe3;

    sget-object v1, Llyiahf/vczjk/dn1;->OooO0O0:Llyiahf/vczjk/op3;

    iput-object v1, p0, Llyiahf/vczjk/j00;->OooOoOO:Llyiahf/vczjk/en1;

    const/4 v1, 0x1

    iput v1, p0, Llyiahf/vczjk/j00;->OooOoo0:I

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/j00;->OooOooO:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/j00;->OooOooo:Llyiahf/vczjk/qs5;

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/j00;->Oooo000:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/hg2;)V
    .locals 7

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v0

    new-instance v2, Llyiahf/vczjk/tq8;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/tq8;-><init>(J)V

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOOoo:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOo00:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/un6;

    if-eqz v1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v3

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOo0:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v5

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOo0O:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v6, v0

    check-cast v6, Llyiahf/vczjk/p21;

    move-object v2, p1

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/un6;->OooO0oO(Llyiahf/vczjk/hg2;JFLlyiahf/vczjk/p21;)V

    :cond_0
    return-void
.end method

.method public final OooO00o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOOo:Llyiahf/vczjk/to1;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo0(Llyiahf/vczjk/xr1;Ljava/util/concurrent/CancellationException;)V

    :cond_0
    iput-object v1, p0, Llyiahf/vczjk/j00;->OooOOo:Llyiahf/vczjk/to1;

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOo:Llyiahf/vczjk/un6;

    instance-of v2, v0, Llyiahf/vczjk/no7;

    if-eqz v2, :cond_1

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/no7;

    :cond_1
    if-eqz v1, :cond_2

    invoke-interface {v1}, Llyiahf/vczjk/no7;->OooO00o()V

    :cond_2
    return-void
.end method

.method public final OooO0O0()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOOo:Llyiahf/vczjk/to1;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo0(Llyiahf/vczjk/xr1;Ljava/util/concurrent/CancellationException;)V

    :cond_0
    iput-object v1, p0, Llyiahf/vczjk/j00;->OooOOo:Llyiahf/vczjk/to1;

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOo:Llyiahf/vczjk/un6;

    instance-of v2, v0, Llyiahf/vczjk/no7;

    if-eqz v2, :cond_1

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/no7;

    :cond_1
    if-eqz v1, :cond_2

    invoke-interface {v1}, Llyiahf/vczjk/no7;->OooO0O0()V

    :cond_2
    return-void
.end method

.method public final OooO0OO()V
    .locals 4

    const-string v0, "AsyncImagePainter.onRemembered"

    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOOo:Llyiahf/vczjk/to1;

    if-nez v0, :cond_3

    invoke-static {}, Llyiahf/vczjk/vl6;->OooO0O0()Llyiahf/vczjk/u99;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v1, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    iget-object v1, v1, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    invoke-static {v0, v1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/j00;->OooOOo:Llyiahf/vczjk/to1;

    iget-object v1, p0, Llyiahf/vczjk/j00;->OooOo:Llyiahf/vczjk/un6;

    instance-of v2, v1, Llyiahf/vczjk/no7;

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    check-cast v1, Llyiahf/vczjk/no7;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_2

    :cond_0
    move-object v1, v3

    :goto_0
    if-eqz v1, :cond_1

    invoke-interface {v1}, Llyiahf/vczjk/no7;->OooO0OO()V

    :cond_1
    iget-boolean v1, p0, Llyiahf/vczjk/j00;->OooOoo:Z

    if-eqz v1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOooo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/kv3;

    invoke-static {v0}, Llyiahf/vczjk/kv3;->OooO00o(Llyiahf/vczjk/kv3;)Llyiahf/vczjk/jv3;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/j00;->Oooo000:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/fv3;

    check-cast v1, Llyiahf/vczjk/ii7;

    iget-object v1, v1, Llyiahf/vczjk/ii7;->OooO0O0:Llyiahf/vczjk/k32;

    iput-object v1, v0, Llyiahf/vczjk/jv3;->OooO0O0:Llyiahf/vczjk/k32;

    iput-object v3, v0, Llyiahf/vczjk/jv3;->OooOOOo:Llyiahf/vczjk/r78;

    invoke-virtual {v0}, Llyiahf/vczjk/jv3;->OooO00o()Llyiahf/vczjk/kv3;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/a00;

    iget-object v0, v0, Llyiahf/vczjk/kv3;->OooOoO:Llyiahf/vczjk/k32;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/OooOO0O;->OooO00o:Llyiahf/vczjk/k32;

    invoke-direct {v1, v3}, Llyiahf/vczjk/a00;-><init>(Llyiahf/vczjk/un6;)V

    invoke-virtual {p0, v1}, Llyiahf/vczjk/j00;->OooOO0O(Llyiahf/vczjk/c00;)V

    goto :goto_1

    :cond_2
    new-instance v1, Llyiahf/vczjk/f00;

    invoke-direct {v1, p0, v3}, Llyiahf/vczjk/f00;-><init>(Llyiahf/vczjk/j00;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x3

    invoke-static {v0, v3, v3, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_3
    :goto_1
    invoke-static {}, Landroid/os/Trace;->endSection()V

    return-void

    :goto_2
    invoke-static {}, Landroid/os/Trace;->endSection()V

    throw v0
.end method

.method public final OooO0Oo(F)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOo0:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    const/4 p1, 0x1

    return p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/p21;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOo0O:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    const/4 p1, 0x1

    return p1
.end method

.method public final OooO0oo()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOo00:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/un6;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/un6;->OooO0oo()J

    move-result-wide v0

    return-wide v0

    :cond_0
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    return-wide v0
.end method

.method public final OooOO0(Landroid/graphics/drawable/Drawable;)Llyiahf/vczjk/un6;
    .locals 8

    instance-of v0, p1, Landroid/graphics/drawable/BitmapDrawable;

    if-eqz v0, :cond_0

    check-cast p1, Landroid/graphics/drawable/BitmapDrawable;

    invoke-virtual {p1}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/kd;

    invoke-direct {v0, p1}, Llyiahf/vczjk/kd;-><init>(Landroid/graphics/Bitmap;)V

    iget v1, p0, Llyiahf/vczjk/j00;->OooOoo0:I

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v2

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result p1

    int-to-long v2, v2

    const/16 v4, 0x20

    shl-long/2addr v2, v4

    int-to-long v4, p1

    const-wide v6, 0xffffffffL

    and-long/2addr v4, v6

    or-long/2addr v2, v4

    new-instance p1, Llyiahf/vczjk/cd0;

    invoke-direct {p1, v0, v2, v3}, Llyiahf/vczjk/cd0;-><init>(Llyiahf/vczjk/lu3;J)V

    iput v1, p1, Llyiahf/vczjk/cd0;->OooOo00:I

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/pg2;

    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/pg2;-><init>(Landroid/graphics/drawable/Drawable;)V

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/c00;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOo0o:Llyiahf/vczjk/c00;

    iget-object v1, p0, Llyiahf/vczjk/j00;->OooOoO0:Llyiahf/vczjk/oe3;

    invoke-interface {v1, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c00;

    iput-object p1, p0, Llyiahf/vczjk/j00;->OooOo0o:Llyiahf/vczjk/c00;

    iget-object v1, p0, Llyiahf/vczjk/j00;->OooOooO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    instance-of v1, p1, Llyiahf/vczjk/b00;

    if-eqz v1, :cond_0

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/b00;

    iget-object v1, v1, Llyiahf/vczjk/b00;->OooO0O0:Llyiahf/vczjk/l99;

    goto :goto_0

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/zz;

    if-eqz v1, :cond_1

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/zz;

    iget-object v1, v1, Llyiahf/vczjk/zz;->OooO0O0:Llyiahf/vczjk/lq2;

    :goto_0
    invoke-virtual {v1}, Llyiahf/vczjk/lv3;->OooO00o()Llyiahf/vczjk/kv3;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/kv3;->OooO0oO:Llyiahf/vczjk/k26;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/c00;->OooO00o()Llyiahf/vczjk/un6;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/j00;->OooOo:Llyiahf/vczjk/un6;

    iget-object v2, p0, Llyiahf/vczjk/j00;->OooOo00:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/j00;->OooOOo:Llyiahf/vczjk/to1;

    if-eqz v1, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/c00;->OooO00o()Llyiahf/vczjk/un6;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/c00;->OooO00o()Llyiahf/vczjk/un6;

    move-result-object v2

    if-eq v1, v2, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/c00;->OooO00o()Llyiahf/vczjk/un6;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/no7;

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    check-cast v0, Llyiahf/vczjk/no7;

    goto :goto_1

    :cond_2
    move-object v0, v2

    :goto_1
    if-eqz v0, :cond_3

    invoke-interface {v0}, Llyiahf/vczjk/no7;->OooO0O0()V

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/c00;->OooO00o()Llyiahf/vczjk/un6;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/no7;

    if-eqz v1, :cond_4

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/no7;

    :cond_4
    if-eqz v2, :cond_5

    invoke-interface {v2}, Llyiahf/vczjk/no7;->OooO0OO()V

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/j00;->OooOoO:Llyiahf/vczjk/fi2;

    if-eqz v0, :cond_6

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fi2;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_6
    return-void
.end method
