.class public final Llyiahf/vczjk/sp;
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


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sp;->$modifier:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/sp;->$backgroundColor:J

    iput-wide p4, p0, Llyiahf/vczjk/sp;->$contentColor:J

    iput p6, p0, Llyiahf/vczjk/sp;->$elevation:F

    iput-object p7, p0, Llyiahf/vczjk/sp;->$contentPadding:Llyiahf/vczjk/bi6;

    iput-object p8, p0, Llyiahf/vczjk/sp;->$content:Llyiahf/vczjk/bf3;

    iput p9, p0, Llyiahf/vczjk/sp;->$$changed:I

    iput p10, p0, Llyiahf/vczjk/sp;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/sp;->$modifier:Llyiahf/vczjk/kl5;

    iget-wide v1, p0, Llyiahf/vczjk/sp;->$backgroundColor:J

    iget-wide v3, p0, Llyiahf/vczjk/sp;->$contentColor:J

    iget v5, p0, Llyiahf/vczjk/sp;->$elevation:F

    iget-object v6, p0, Llyiahf/vczjk/sp;->$contentPadding:Llyiahf/vczjk/bi6;

    iget-object v7, p0, Llyiahf/vczjk/sp;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/sp;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget v10, p0, Llyiahf/vczjk/sp;->$$default:I

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/vp;->OooO0O0(Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
