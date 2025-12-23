.class public final Llyiahf/vczjk/vj9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0oO:Llyiahf/vczjk/era;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/lr5;

.field public final OooO0O0:Llyiahf/vczjk/lr5;

.field public final OooO0OO:Llyiahf/vczjk/qr5;

.field public OooO0Oo:Llyiahf/vczjk/wj7;

.field public final OooO0o:Llyiahf/vczjk/qs5;

.field public OooO0o0:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/uj9;->OooOOO:Llyiahf/vczjk/uj9;

    sget-object v1, Llyiahf/vczjk/o68;->OoooO00:Llyiahf/vczjk/o68;

    invoke-static {v1, v0}, Llyiahf/vczjk/vc6;->Oooo0(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/era;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/vj9;->OooO0oO:Llyiahf/vczjk/era;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/nf6;F)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/vj9;->OooO00o:Llyiahf/vczjk/lr5;

    const/4 p2, 0x0

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/vj9;->OooO0O0:Llyiahf/vczjk/lr5;

    const/4 p2, 0x0

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/vj9;->OooO0OO:Llyiahf/vczjk/qr5;

    sget-object p2, Llyiahf/vczjk/wj7;->OooO0o0:Llyiahf/vczjk/wj7;

    iput-object p2, p0, Llyiahf/vczjk/vj9;->OooO0Oo:Llyiahf/vczjk/wj7;

    sget-wide v0, Llyiahf/vczjk/gn9;->OooO0O0:J

    iput-wide v0, p0, Llyiahf/vczjk/vj9;->OooO0o0:J

    sget-object p2, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    invoke-static {p1, p2}, Landroidx/compose/runtime/OooO0o;->OooO(Ljava/lang/Object;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vj9;->OooO0o:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vj9;->OooO00o:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    return v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/nf6;Llyiahf/vczjk/wj7;II)V
    .locals 8

    sub-int/2addr p4, p3

    int-to-float p4, p4

    iget-object v0, p0, Llyiahf/vczjk/vj9;->OooO0O0:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0, p4}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iget-object v0, p0, Llyiahf/vczjk/vj9;->OooO0Oo:Llyiahf/vczjk/wj7;

    iget v1, v0, Llyiahf/vczjk/wj7;->OooO00o:F

    iget v2, p2, Llyiahf/vczjk/wj7;->OooO00o:F

    cmpg-float v1, v2, v1

    iget-object v3, p0, Llyiahf/vczjk/vj9;->OooO00o:Llyiahf/vczjk/lr5;

    const/4 v4, 0x0

    iget v5, p2, Llyiahf/vczjk/wj7;->OooO0O0:F

    if-nez v1, :cond_0

    iget v0, v0, Llyiahf/vczjk/wj7;->OooO0O0:F

    cmpg-float v0, v5, v0

    if-nez v0, :cond_0

    goto :goto_4

    :cond_0
    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne p1, v0, :cond_1

    const/4 p1, 0x1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_2

    move v2, v5

    :cond_2
    if-eqz p1, :cond_3

    iget p1, p2, Llyiahf/vczjk/wj7;->OooO0Oo:F

    goto :goto_1

    :cond_3
    iget p1, p2, Llyiahf/vczjk/wj7;->OooO0OO:F

    :goto_1
    invoke-virtual {p0}, Llyiahf/vczjk/vj9;->OooO00o()F

    move-result v0

    int-to-float v1, p3

    add-float v5, v0, v1

    cmpl-float v6, p1, v5

    if-lez v6, :cond_4

    :goto_2
    sub-float/2addr p1, v5

    goto :goto_3

    :cond_4
    cmpg-float v6, v2, v0

    if-gez v6, :cond_5

    sub-float v7, p1, v2

    cmpl-float v7, v7, v1

    if-lez v7, :cond_5

    goto :goto_2

    :cond_5
    if-gez v6, :cond_6

    sub-float/2addr p1, v2

    cmpg-float p1, p1, v1

    if-gtz p1, :cond_6

    sub-float p1, v2, v0

    goto :goto_3

    :cond_6
    move p1, v4

    :goto_3
    invoke-virtual {p0}, Llyiahf/vczjk/vj9;->OooO00o()F

    move-result v0

    add-float/2addr v0, p1

    move-object p1, v3

    check-cast p1, Llyiahf/vczjk/zv8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iput-object p2, p0, Llyiahf/vczjk/vj9;->OooO0Oo:Llyiahf/vczjk/wj7;

    :goto_4
    invoke-virtual {p0}, Llyiahf/vczjk/vj9;->OooO00o()F

    move-result p1

    invoke-static {p1, v4, p4}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p1

    check-cast v3, Llyiahf/vczjk/zv8;

    invoke-virtual {v3, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iget-object p1, p0, Llyiahf/vczjk/vj9;->OooO0OO:Llyiahf/vczjk/qr5;

    check-cast p1, Llyiahf/vczjk/bw8;

    invoke-virtual {p1, p3}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    return-void
.end method
