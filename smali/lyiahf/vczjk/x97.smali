.class public final synthetic Llyiahf/vczjk/x97;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:F

.field public final synthetic OooOOo0:I

.field public final synthetic OooOOoo:I

.field public final synthetic OooOo00:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;JFJIFII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/x97;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/x97;->OooOOO:J

    iput p4, p0, Llyiahf/vczjk/x97;->OooOOOO:F

    iput-wide p5, p0, Llyiahf/vczjk/x97;->OooOOOo:J

    iput p7, p0, Llyiahf/vczjk/x97;->OooOOo0:I

    iput p8, p0, Llyiahf/vczjk/x97;->OooOOo:F

    iput p9, p0, Llyiahf/vczjk/x97;->OooOOoo:I

    iput p10, p0, Llyiahf/vczjk/x97;->OooOo00:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/x97;->OooOOoo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget v7, p0, Llyiahf/vczjk/x97;->OooOOo:F

    iget v10, p0, Llyiahf/vczjk/x97;->OooOo00:I

    iget-object v0, p0, Llyiahf/vczjk/x97;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-wide v1, p0, Llyiahf/vczjk/x97;->OooOOO:J

    iget v3, p0, Llyiahf/vczjk/x97;->OooOOOO:F

    iget-wide v4, p0, Llyiahf/vczjk/x97;->OooOOOo:J

    iget v6, p0, Llyiahf/vczjk/x97;->OooOOo0:I

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/ea7;->OooO00o(Llyiahf/vczjk/kl5;JFJIFLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
