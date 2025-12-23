.class public final Llyiahf/vczjk/cd2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $color:J

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $startIndent:F

.field final synthetic $thickness:F


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;JFFII)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cd2;->$modifier:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/cd2;->$color:J

    iput p4, p0, Llyiahf/vczjk/cd2;->$thickness:F

    iput p5, p0, Llyiahf/vczjk/cd2;->$startIndent:F

    iput p6, p0, Llyiahf/vczjk/cd2;->$$changed:I

    iput p7, p0, Llyiahf/vczjk/cd2;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/cd2;->$modifier:Llyiahf/vczjk/kl5;

    iget-wide v1, p0, Llyiahf/vczjk/cd2;->$color:J

    iget v3, p0, Llyiahf/vczjk/cd2;->$thickness:F

    iget v4, p0, Llyiahf/vczjk/cd2;->$startIndent:F

    iget p1, p0, Llyiahf/vczjk/cd2;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget v7, p0, Llyiahf/vczjk/cd2;->$$default:I

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/tg0;->OooO(Llyiahf/vczjk/kl5;JFFLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
