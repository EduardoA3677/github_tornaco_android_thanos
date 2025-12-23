.class public final synthetic Llyiahf/vczjk/g35;
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


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/qj8;Ljava/util/List;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g35;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/g35;->OooOOO:J

    iput-wide p4, p0, Llyiahf/vczjk/g35;->OooOOOO:J

    iput-object p6, p0, Llyiahf/vczjk/g35;->OooOOOo:Llyiahf/vczjk/qj8;

    iput-object p7, p0, Llyiahf/vczjk/g35;->OooOOo0:Ljava/util/List;

    iput p8, p0, Llyiahf/vczjk/g35;->OooOOo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p1, p0, Llyiahf/vczjk/g35;->OooOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget-object v0, p0, Llyiahf/vczjk/g35;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-wide v1, p0, Llyiahf/vczjk/g35;->OooOOO:J

    iget-wide v3, p0, Llyiahf/vczjk/g35;->OooOOOO:J

    iget-object v5, p0, Llyiahf/vczjk/g35;->OooOOOo:Llyiahf/vczjk/qj8;

    iget-object v6, p0, Llyiahf/vczjk/g35;->OooOOo0:Ljava/util/List;

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/so8;->OooOO0(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/qj8;Ljava/util/List;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
