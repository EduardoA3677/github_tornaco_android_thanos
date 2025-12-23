.class public final synthetic Llyiahf/vczjk/e35;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:Ljava/util/List;

.field public final synthetic OooOOoo:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/qj8;Ljava/util/List;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/e35;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/e35;->OooOOO:J

    iput-wide p4, p0, Llyiahf/vczjk/e35;->OooOOOO:J

    iput-object p6, p0, Llyiahf/vczjk/e35;->OooOOOo:Llyiahf/vczjk/qj8;

    iput-object p7, p0, Llyiahf/vczjk/e35;->OooOOo0:Ljava/util/List;

    iput p8, p0, Llyiahf/vczjk/e35;->OooOOo:I

    iput p9, p0, Llyiahf/vczjk/e35;->OooOOoo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/e35;->OooOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget-object v6, p0, Llyiahf/vczjk/e35;->OooOOo0:Ljava/util/List;

    iget v9, p0, Llyiahf/vczjk/e35;->OooOOoo:I

    iget-object v0, p0, Llyiahf/vczjk/e35;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-wide v1, p0, Llyiahf/vczjk/e35;->OooOOO:J

    iget-wide v3, p0, Llyiahf/vczjk/e35;->OooOOOO:J

    iget-object v5, p0, Llyiahf/vczjk/e35;->OooOOOo:Llyiahf/vczjk/qj8;

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/so8;->OooO0OO(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/qj8;Ljava/util/List;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
