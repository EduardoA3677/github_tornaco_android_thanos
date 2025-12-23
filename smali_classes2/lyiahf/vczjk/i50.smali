.class public final synthetic Llyiahf/vczjk/i50;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOO0:Ljava/lang/String;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:F

.field public final synthetic OooOOoo:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Llyiahf/vczjk/kl5;JJFII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i50;->OooOOO0:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/i50;->OooOOO:Llyiahf/vczjk/kl5;

    iput-wide p3, p0, Llyiahf/vczjk/i50;->OooOOOO:J

    iput-wide p5, p0, Llyiahf/vczjk/i50;->OooOOOo:J

    iput p7, p0, Llyiahf/vczjk/i50;->OooOOo0:F

    iput p8, p0, Llyiahf/vczjk/i50;->OooOOo:I

    iput p9, p0, Llyiahf/vczjk/i50;->OooOOoo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/i50;->OooOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget v6, p0, Llyiahf/vczjk/i50;->OooOOo0:F

    iget v9, p0, Llyiahf/vczjk/i50;->OooOOoo:I

    iget-object v0, p0, Llyiahf/vczjk/i50;->OooOOO0:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/i50;->OooOOO:Llyiahf/vczjk/kl5;

    iget-wide v2, p0, Llyiahf/vczjk/i50;->OooOOOO:J

    iget-wide v4, p0, Llyiahf/vczjk/i50;->OooOOOo:J

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/nqa;->OooO0o(Ljava/lang/String;Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
