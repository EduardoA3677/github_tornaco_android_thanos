.class public final Llyiahf/vczjk/ba7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $backgroundColor:J

.field final synthetic $color:J

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $strokeCap:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;JJIII)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ba7;->$modifier:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/ba7;->$color:J

    iput-wide p4, p0, Llyiahf/vczjk/ba7;->$backgroundColor:J

    iput p6, p0, Llyiahf/vczjk/ba7;->$strokeCap:I

    iput p7, p0, Llyiahf/vczjk/ba7;->$$changed:I

    iput p8, p0, Llyiahf/vczjk/ba7;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/ba7;->$modifier:Llyiahf/vczjk/kl5;

    iget-wide v1, p0, Llyiahf/vczjk/ba7;->$color:J

    iget-wide v3, p0, Llyiahf/vczjk/ba7;->$backgroundColor:J

    iget v5, p0, Llyiahf/vczjk/ba7;->$strokeCap:I

    iget p1, p0, Llyiahf/vczjk/ba7;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget v8, p0, Llyiahf/vczjk/ba7;->$$default:I

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/fa7;->OooO0O0(Llyiahf/vczjk/kl5;JJILlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
