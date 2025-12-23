.class public final Llyiahf/vczjk/sa9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $border:Llyiahf/vczjk/se0;

.field final synthetic $color:J

.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $contentColor:J

.field final synthetic $elevation:F

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $shape:Llyiahf/vczjk/qj8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sa9;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/sa9;->$shape:Llyiahf/vczjk/qj8;

    iput-wide p3, p0, Llyiahf/vczjk/sa9;->$color:J

    iput-wide p5, p0, Llyiahf/vczjk/sa9;->$contentColor:J

    iput-object p7, p0, Llyiahf/vczjk/sa9;->$border:Llyiahf/vczjk/se0;

    iput p8, p0, Llyiahf/vczjk/sa9;->$elevation:F

    iput-object p9, p0, Llyiahf/vczjk/sa9;->$content:Llyiahf/vczjk/ze3;

    iput p10, p0, Llyiahf/vczjk/sa9;->$$changed:I

    iput p11, p0, Llyiahf/vczjk/sa9;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/sa9;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v1, p0, Llyiahf/vczjk/sa9;->$shape:Llyiahf/vczjk/qj8;

    iget-wide v2, p0, Llyiahf/vczjk/sa9;->$color:J

    iget-wide v4, p0, Llyiahf/vczjk/sa9;->$contentColor:J

    iget-object v6, p0, Llyiahf/vczjk/sa9;->$border:Llyiahf/vczjk/se0;

    iget v7, p0, Llyiahf/vczjk/sa9;->$elevation:F

    iget-object v8, p0, Llyiahf/vczjk/sa9;->$content:Llyiahf/vczjk/ze3;

    iget p1, p0, Llyiahf/vczjk/sa9;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v10

    iget v11, p0, Llyiahf/vczjk/sa9;->$$default:I

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/rd3;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
