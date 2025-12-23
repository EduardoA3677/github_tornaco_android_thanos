.class public final synthetic Llyiahf/vczjk/te7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/bf7;

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:J

.field public final synthetic OooOOoo:I


# direct methods
.method public synthetic constructor <init>(ZLlyiahf/vczjk/bf7;Llyiahf/vczjk/kl5;JJII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/te7;->OooOOO0:Z

    iput-object p2, p0, Llyiahf/vczjk/te7;->OooOOO:Llyiahf/vczjk/bf7;

    iput-object p3, p0, Llyiahf/vczjk/te7;->OooOOOO:Llyiahf/vczjk/kl5;

    iput-wide p4, p0, Llyiahf/vczjk/te7;->OooOOOo:J

    iput-wide p6, p0, Llyiahf/vczjk/te7;->OooOOo0:J

    iput p8, p0, Llyiahf/vczjk/te7;->OooOOo:I

    iput p9, p0, Llyiahf/vczjk/te7;->OooOOoo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/te7;->OooOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget-wide v5, p0, Llyiahf/vczjk/te7;->OooOOo0:J

    iget v9, p0, Llyiahf/vczjk/te7;->OooOOoo:I

    iget-boolean v0, p0, Llyiahf/vczjk/te7;->OooOOO0:Z

    iget-object v1, p0, Llyiahf/vczjk/te7;->OooOOO:Llyiahf/vczjk/bf7;

    iget-object v2, p0, Llyiahf/vczjk/te7;->OooOOOO:Llyiahf/vczjk/kl5;

    iget-wide v3, p0, Llyiahf/vczjk/te7;->OooOOOo:J

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/ue7;->OooO00o(ZLlyiahf/vczjk/bf7;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
