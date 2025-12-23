.class public final Llyiahf/vczjk/td6;
.super Llyiahf/vczjk/b23;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/td6;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/td6;

    const/4 v1, 0x0

    const/4 v2, 0x3

    invoke-direct {v0, v1, v1, v2}, Llyiahf/vczjk/b23;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/td6;->OooO0Oo:Llyiahf/vczjk/td6;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/j11;Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V
    .locals 0

    iget p1, p3, Llyiahf/vczjk/os8;->OooOOO:I

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    const-string p1, "Cannot reset when inserting"

    invoke-static {p1}, Llyiahf/vczjk/ag1;->OooO0OO(Ljava/lang/String;)V

    :goto_0
    invoke-virtual {p3}, Llyiahf/vczjk/os8;->OooOooo()V

    const/4 p1, 0x0

    iput p1, p3, Llyiahf/vczjk/os8;->OooOo00:I

    invoke-virtual {p3}, Llyiahf/vczjk/os8;->OooOOO0()I

    move-result p2

    iget p4, p3, Llyiahf/vczjk/os8;->OooO0oo:I

    sub-int/2addr p2, p4

    iput p2, p3, Llyiahf/vczjk/os8;->OooOo0:I

    iput p1, p3, Llyiahf/vczjk/os8;->OooO:I

    iput p1, p3, Llyiahf/vczjk/os8;->OooOO0:I

    iput p1, p3, Llyiahf/vczjk/os8;->OooOOOO:I

    return-void
.end method
