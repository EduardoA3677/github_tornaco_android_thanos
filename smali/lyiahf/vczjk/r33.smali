.class public final synthetic Llyiahf/vczjk/r33;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOO:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:Llyiahf/vczjk/h33;

.field public final synthetic OooOOo0:J

.field public final synthetic OooOOoo:Llyiahf/vczjk/a91;

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/h33;Llyiahf/vczjk/a91;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/r33;->OooOOO0:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/r33;->OooOOO:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/r33;->OooOOOO:Llyiahf/vczjk/qj8;

    iput-wide p4, p0, Llyiahf/vczjk/r33;->OooOOOo:J

    iput-wide p6, p0, Llyiahf/vczjk/r33;->OooOOo0:J

    iput-object p8, p0, Llyiahf/vczjk/r33;->OooOOo:Llyiahf/vczjk/h33;

    iput-object p9, p0, Llyiahf/vczjk/r33;->OooOOoo:Llyiahf/vczjk/a91;

    iput p10, p0, Llyiahf/vczjk/r33;->OooOo00:I

    iput p11, p0, Llyiahf/vczjk/r33;->OooOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/r33;->OooOo00:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v10

    iget-object v8, p0, Llyiahf/vczjk/r33;->OooOOoo:Llyiahf/vczjk/a91;

    iget v11, p0, Llyiahf/vczjk/r33;->OooOo0:I

    iget-object v0, p0, Llyiahf/vczjk/r33;->OooOOO0:Llyiahf/vczjk/le3;

    iget-object v1, p0, Llyiahf/vczjk/r33;->OooOOO:Llyiahf/vczjk/kl5;

    iget-object v2, p0, Llyiahf/vczjk/r33;->OooOOOO:Llyiahf/vczjk/qj8;

    iget-wide v3, p0, Llyiahf/vczjk/r33;->OooOOOo:J

    iget-wide v5, p0, Llyiahf/vczjk/r33;->OooOOo0:J

    iget-object v7, p0, Llyiahf/vczjk/r33;->OooOOo:Llyiahf/vczjk/h33;

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/v33;->OooO0OO(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/h33;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
