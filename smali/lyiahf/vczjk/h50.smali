.class public final synthetic Llyiahf/vczjk/h50;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/a91;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/h50;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/h50;->OooOOO:J

    iput-wide p4, p0, Llyiahf/vczjk/h50;->OooOOOO:J

    iput-object p6, p0, Llyiahf/vczjk/h50;->OooOOOo:Llyiahf/vczjk/a91;

    iput p7, p0, Llyiahf/vczjk/h50;->OooOOo0:I

    iput p8, p0, Llyiahf/vczjk/h50;->OooOOo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/h50;->OooOOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget-object v5, p0, Llyiahf/vczjk/h50;->OooOOOo:Llyiahf/vczjk/a91;

    iget v8, p0, Llyiahf/vczjk/h50;->OooOOo:I

    iget-object v0, p0, Llyiahf/vczjk/h50;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-wide v1, p0, Llyiahf/vczjk/h50;->OooOOO:J

    iget-wide v3, p0, Llyiahf/vczjk/h50;->OooOOOO:J

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/l50;->OooO00o(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
