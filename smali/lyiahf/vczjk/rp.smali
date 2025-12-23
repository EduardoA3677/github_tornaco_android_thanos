.class public final Llyiahf/vczjk/rp;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $backgroundColor:J

.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $contentColor:J

.field final synthetic $contentPadding:Llyiahf/vczjk/bi6;

.field final synthetic $elevation:F

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $shape:Llyiahf/vczjk/qj8;

.field final synthetic $windowInsets:Llyiahf/vczjk/kna;


# direct methods
.method public constructor <init>(JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/qj8;Llyiahf/vczjk/kna;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/rp;->$backgroundColor:J

    iput-wide p3, p0, Llyiahf/vczjk/rp;->$contentColor:J

    iput p5, p0, Llyiahf/vczjk/rp;->$elevation:F

    iput-object p6, p0, Llyiahf/vczjk/rp;->$contentPadding:Llyiahf/vczjk/bi6;

    iput-object p7, p0, Llyiahf/vczjk/rp;->$shape:Llyiahf/vczjk/qj8;

    iput-object p8, p0, Llyiahf/vczjk/rp;->$windowInsets:Llyiahf/vczjk/kna;

    iput-object p9, p0, Llyiahf/vczjk/rp;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p10, p0, Llyiahf/vczjk/rp;->$content:Llyiahf/vczjk/bf3;

    iput p11, p0, Llyiahf/vczjk/rp;->$$changed:I

    iput p12, p0, Llyiahf/vczjk/rp;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-wide v0, p0, Llyiahf/vczjk/rp;->$backgroundColor:J

    iget-wide v2, p0, Llyiahf/vczjk/rp;->$contentColor:J

    iget v4, p0, Llyiahf/vczjk/rp;->$elevation:F

    iget-object v5, p0, Llyiahf/vczjk/rp;->$contentPadding:Llyiahf/vczjk/bi6;

    iget-object v6, p0, Llyiahf/vczjk/rp;->$shape:Llyiahf/vczjk/qj8;

    iget-object v7, p0, Llyiahf/vczjk/rp;->$windowInsets:Llyiahf/vczjk/kna;

    iget-object v8, p0, Llyiahf/vczjk/rp;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v9, p0, Llyiahf/vczjk/rp;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/rp;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    iget v12, p0, Llyiahf/vczjk/rp;->$$default:I

    invoke-static/range {v0 .. v12}, Llyiahf/vczjk/vp;->OooO00o(JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/qj8;Llyiahf/vczjk/kna;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
