.class public final Llyiahf/vczjk/ku8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $actionColor:J

.field final synthetic $actionOnNewLine:Z

.field final synthetic $backgroundColor:J

.field final synthetic $contentColor:J

.field final synthetic $elevation:F

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $shape:Llyiahf/vczjk/qj8;

.field final synthetic $snackbarData:Llyiahf/vczjk/ht8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;JJJFII)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ku8;->$modifier:Llyiahf/vczjk/kl5;

    iput-boolean p2, p0, Llyiahf/vczjk/ku8;->$actionOnNewLine:Z

    iput-object p3, p0, Llyiahf/vczjk/ku8;->$shape:Llyiahf/vczjk/qj8;

    iput-wide p4, p0, Llyiahf/vczjk/ku8;->$backgroundColor:J

    iput-wide p6, p0, Llyiahf/vczjk/ku8;->$contentColor:J

    iput-wide p8, p0, Llyiahf/vczjk/ku8;->$actionColor:J

    iput p10, p0, Llyiahf/vczjk/ku8;->$elevation:F

    iput p11, p0, Llyiahf/vczjk/ku8;->$$changed:I

    iput p12, p0, Llyiahf/vczjk/ku8;->$$default:I

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

    iget-object v0, p0, Llyiahf/vczjk/ku8;->$modifier:Llyiahf/vczjk/kl5;

    iget-boolean v1, p0, Llyiahf/vczjk/ku8;->$actionOnNewLine:Z

    iget-object v2, p0, Llyiahf/vczjk/ku8;->$shape:Llyiahf/vczjk/qj8;

    iget-wide v3, p0, Llyiahf/vczjk/ku8;->$backgroundColor:J

    iget-wide v5, p0, Llyiahf/vczjk/ku8;->$contentColor:J

    iget-wide v7, p0, Llyiahf/vczjk/ku8;->$actionColor:J

    iget v9, p0, Llyiahf/vczjk/ku8;->$elevation:F

    iget p1, p0, Llyiahf/vczjk/ku8;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    iget v12, p0, Llyiahf/vczjk/ku8;->$$default:I

    invoke-static/range {v0 .. v12}, Llyiahf/vczjk/mu8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;JJJFLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
